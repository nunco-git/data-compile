const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");
admin.initializeApp();
const db = admin.firestore();

// [보안 수정] 제출 전용 비밀번호(surveyPw) 확인을 서버(Cloud Functions)에서 처리한다.
// 기존에는 브라우저가 managers/{managerId} 문서를 통째로 읽어와 비밀번호를
// 자바스크립트로 비교했는데, 이 방식은 Firestore 규칙상 그 문서를 로그인 없이
// 읽을 수 있어야만 동작하고, 그러면 평문 비밀번호가 누구에게나 노출된다.
// 이제는 브라우저가 이 함수만 호출하고, 실제 비교와 managers 문서 읽기는
// 전부 서버 쪽(관리자 권한, Firestore 규칙의 영향을 받지 않음)에서 이루어지며,
// 브라우저에는 비밀번호가 절대 전달되지 않는다.
exports.verifySurveyAccess = onCall({ enforceAppCheck: true }, async (request) => {
  const agencyCode = (request.data && request.data.agencyCode || "").trim();
  const password = (request.data && request.data.password || "").trim();

  if (!agencyCode || !password) {
    throw new HttpsError("invalid-argument", "접속 코드와 비밀번호를 모두 입력해주세요.");
  }

  const codeSnap = await db.collection("system").doc("agency_code_index").get();
  const codeMap = codeSnap.exists ? codeSnap.data() : {};
  const managerUid = codeMap[agencyCode];
  if (!managerUid) {
    return { ok: false, reason: "NOT_FOUND" };
  }

  const managerSnap = await db.collection("managers").doc(managerUid).get();
  if (!managerSnap.exists) {
    return { ok: false, reason: "NOT_FOUND" };
  }

  const managerData = managerSnap.data();
  if (!managerData.surveyPw || managerData.surveyPw !== password) {
    return { ok: false, reason: "WRONG_PASSWORD" };
  }

  // 비밀번호와 무관한, 화면 표시에 필요한 값만 돌려준다 (surveyPw는 절대 포함하지 않음).
  return {
    ok: true,
    managerUid: managerUid,
    agencyLists: managerData.agencyLists || [],
  };
});

// ---------------------------------------------------------------------
// [보안 수정] 설문 응답 "제출" 자체도 서버에서 처리한다.
// 기존에는 verifySurveyAccess로 비밀번호를 확인한 뒤, 그 결과와 무관하게
// 브라우저가 Firestore에 직접 .add()로 응답 문서를 썼다. 이 방식은
// Firestore 규칙이 request.auth를 확인할 방법이 없어서 사실상 누구나
// (비밀번호 확인 절차를 거치지 않고도) responses 문서를 위조해 넣을 수 있었다.
// 이제는 제출 시점에도 비밀번호/회차/기관명을 다시 서버에서 검증한 뒤
// Admin 권한(Firestore 규칙의 영향을 받지 않음)으로 대신 기록한다.
// firestore.rules 쪽 responses의 allow create는 false로 막아서
// 클라이언트가 이 함수를 거치지 않고는 절대 쓸 수 없게 한다.
exports.submitSurveyResponse = onCall({ enforceAppCheck: true }, async (request) => {
  const data = request.data || {};
  const agencyCode = String(data.agencyCode || "").trim();
  const password = String(data.password || "").trim();
  const roundId = String(data.roundId || "").trim();
  const agencyName = String(data.agencyName || "").trim();
  const payload = data.payload; // { customAnswers?, gridRows?, templateSheets? } 등 기존 docData의 나머지 필드

  if (!agencyCode || !password || !roundId || !agencyName) {
    throw new HttpsError("invalid-argument", "필수 정보가 누락되었습니다.");
  }
  if (agencyName.length >= 200) {
    throw new HttpsError("invalid-argument", "기관명이 너무 깁니다.");
  }

  // 1) 비밀번호/접속코드 재검증 (verifySurveyAccess와 동일한 로직)
  const codeSnap = await db.collection("system").doc("agency_code_index").get();
  const codeMap = codeSnap.exists ? codeSnap.data() : {};
  const managerUid = codeMap[agencyCode];
  if (!managerUid) {
    throw new HttpsError("permission-denied", "존재하지 않는 접속 코드입니다.");
  }

  const managerSnap = await db.collection("managers").doc(managerUid).get();
  if (!managerSnap.exists) {
    throw new HttpsError("permission-denied", "존재하지 않는 접속 코드입니다.");
  }
  const managerData = managerSnap.data();
  if (!managerData.surveyPw || managerData.surveyPw !== password) {
    throw new HttpsError("permission-denied", "제출 전용 비밀번호가 올바르지 않습니다.");
  }

  // 2) 회차가 실제로 이 관리자 소속이고 열려있는지 확인
  const roundSnap = await db
    .collection("managers").doc(managerUid)
    .collection("rounds").doc(roundId).get();
  if (!roundSnap.exists) {
    throw new HttpsError("not-found", "존재하지 않는 회차입니다.");
  }
  const roundData = roundSnap.data();
  if (roundData.status !== "open") {
    throw new HttpsError("failed-precondition", "마감된 회차입니다.");
  }

  // 3) 기관명 확인 - 회차별 "취합 대상 명단" 기준
  //    - 회차에 대상 명단이 지정되어 있으면: 반드시 그 명단 안의 기관만 제출 가능
  //      (다른 명단의 기관이 섞여 들어오는 것을 서버에서 차단)
  //    - 지정되지 않았으면: 기존과 동일하게 전체 명단 중 하나여야 함
  //      (관리자가 명단을 하나도 안 만들어둔 경우엔 자유 입력 허용)
  const agencyLists = managerData.agencyLists || [];
  const namesOf = (list) =>
    (list && Array.isArray(list.agencies) ? list.agencies : [])
      .map((n) => String(n || "").trim())
      .filter((n) => n);

  const targetList = roundData.targetAgencyListId
    ? agencyLists.find((l) => l && l.id === roundData.targetAgencyListId)
    : null;

  if (targetList) {
    if (!namesOf(targetList).includes(agencyName)) {
      throw new HttpsError(
        "permission-denied",
        "이 회차의 취합 대상 기관이 아닙니다. (" + (targetList.name || "지정 명단") + ")"
      );
    }
  } else {
    const allAgencyNames = [];
    agencyLists.forEach((list) => namesOf(list).forEach((n) => allAgencyNames.push(n)));
    if (allAgencyNames.length > 0 && !allAgencyNames.includes(agencyName)) {
      throw new HttpsError("permission-denied", "등록된 기관 목록에 없는 기관명입니다.");
    }
  }

  // 4) 검증 통과 - Admin 권한으로 응답 문서를 대신 기록한다.
  const docData = Object.assign({}, payload || {}, {
    agencyName,
    submittedAt: new Date().toISOString().slice(0, 10),
    submittedAtTs: Date.now(),
  });

  await db
    .collection("managers").doc(managerUid)
    .collection("rounds").doc(roundId)
    .collection("responses").add(docData);

  return { ok: true };
});



// 발송용 지메일 계정 정보. 코드에 직접 적지 않고 Firebase Secret으로 관리한다.
// 배포 전에 아래 두 값을 설정해야 한다:
//   firebase functions:secrets:set GMAIL_USER
//   firebase functions:secrets:set GMAIL_APP_PASSWORD
const gmailUser = defineSecret("GMAIL_USER");
const gmailAppPassword = defineSecret("GMAIL_APP_PASSWORD");

const GOV_EMAIL_PATTERN = /^[^\s@]+@(korea\.kr|[a-zA-Z0-9.-]+\.(go|or|ac|re)\.kr)$/i;
const CODE_TTL_MS = 10 * 60 * 1000; // 10분

exports.sendVerificationCode = onCall(
  { secrets: [gmailUser, gmailAppPassword], enforceAppCheck: true },
  async (request) => {
    console.log("sendVerificationCode 호출 시작");
    if (!request.auth) {
      console.error("실패 지점: request.auth 없음");
      throw new HttpsError("unauthenticated", "로그인이 필요합니다.");
    }
    const email = (request.data && request.data.email || "").trim().toLowerCase();
    console.log("받은 이메일:", email, "/ 정규식 통과 여부:", GOV_EMAIL_PATTERN.test(email));

    if (!GOV_EMAIL_PATTERN.test(email)) {
      // go.kr/or.kr/ac.kr/re.kr/korea.kr 형식이 아니면, 슈퍼관리자가 수동으로
      // 승인한 기록(registration_requests 문서)이 있어야만 통과시킨다.
      const reqSnap = await db.collection("registration_requests").doc(request.auth.uid).get();
      const reqData = reqSnap.exists ? reqSnap.data() : null;
      console.log("승인 기록 조회 결과:", JSON.stringify(reqData));
      if (!reqData || reqData.status !== "approved" || reqData.email !== email) {
        console.error("실패 지점: 관리자 승인 필요 (정규식 불통과 + 승인 기록 없음/불일치)");
        throw new HttpsError(
          "failed-precondition",
          "이 이메일은 관리자 승인이 필요합니다. 먼저 가입 화면에서 승인 요청을 접수해주세요."
        );
      }
    }
    console.log("이메일 형식/승인 검사 통과, 인증번호 생성 진행");

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
    const expiresAt = Date.now() + CODE_TTL_MS;

    // uid별로 하나만 유지 (재발송 시 이전 코드는 자동 무효화됨)
    await db.collection("email_verification_codes").doc(request.auth.uid).set({
      email,
      code,
      expiresAt,
      used: false,
    });

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: gmailUser.value(),
        pass: gmailAppPassword.value(),
      },
    });

    try {
      await transporter.sendMail({
        from: `"자료취합시스템" <${gmailUser.value()}>`,
        to: email,
        subject: "[자료취합시스템] 이메일 인증번호",
        text:
          "소속기관 이메일 인증번호입니다.\n\n" +
          "인증번호: " + code + "\n\n" +
          "10분 이내에 화면에 입력해주세요.\n" +
          "본인이 요청하지 않았다면 이 메일을 무시하셔도 됩니다.",
      });
      console.log("메일 발송 성공:", email);
    } catch (mailErr) {
      // [진단용] 실패 원인을 Cloud Logging에 그대로 남기고, 화면에도 실제 원인이 보이게 전달한다.
      console.error("메일 발송 실패:", mailErr && mailErr.message, mailErr);
      throw new HttpsError("internal", "메일 발송 실패: " + (mailErr && mailErr.message || String(mailErr)));
    }

    return { ok: true };
  }
);

exports.verifyEmailCode = onCall({ enforceAppCheck: true }, async (request) => {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "로그인이 필요합니다.");
  }
  const code = (request.data && request.data.code || "").trim();
  const docRef = db.collection("email_verification_codes").doc(request.auth.uid);
  const snap = await docRef.get();

  if (!snap.exists) return { ok: false, reason: "NOT_REQUESTED" };
  const data = snap.data();
  if (data.used) return { ok: false, reason: "ALREADY_USED" };
  if (Date.now() > data.expiresAt) return { ok: false, reason: "EXPIRED" };
  if (data.code !== code) return { ok: false, reason: "WRONG_CODE" };

  await docRef.update({ used: true });

  // 이 문서는 오직 이 함수(관리자 권한)만 쓸 수 있고, Firestore 규칙이
  // 가입(managers 문서 생성) 시 이 문서의 이메일과 실제 제출한 값이
  // 일치하는지 대조하는 데 사용한다.
  await db.collection("email_verifications").doc(request.auth.uid).set({
    email: data.email,
    verifiedAt: Date.now(),
  });

  return { ok: true, email: data.email };
});
