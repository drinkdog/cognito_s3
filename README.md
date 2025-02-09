# Flask + AWS Cognito + S3 기반 파일 업로드 시스템

## 프로젝트 개요
이 프로젝트는 Flask를 기반으로 AWS Cognito(OAuth 2.0 인증)와 S3(파일 저장소)를 연동하여 안전한 사용자 인증 및 파일 업로드 기능을 제공하는 웹 애플리케이션입니다.

✅ AWS Cognito OAuth 2.0 로그인 지원\n
✅ AWS S3 파일 업로드, 다운로드, 삭제 기능\n
✅ Cognito Federated Identities를 통한 임시 AWS 자격 증명 사용\n
✅ Flask 기반의 RESTful API 및 예외 처리 적용\n

---

## 기술 스택
- Backend: Flask, Python 3
- Authentication: AWS Cognito (OAuth 2.0, OpenID Connect)
- Storage: AWS S3
- AWS Services: Cognito User Pool, Identity Pool, S3, IAM
- Logging & Debugging: Python logging, Flask Debug Mode

---

## 기능 소개
1️⃣ AWS Cognito OAuth 로그인
- AWS Cognito와 OAuth 2.0을 활용하여 사용자 로그인 및 인증 구현
- `authlib` 라이브러리를 활용하여 OIDC 기반 로그인 처리

2️⃣ AWS S3 파일 업로드 및 폴더 관리
- 사용자가 디렉토리를 선택하여 파일 업로드 가능
- S3 Presigned URL을 활용한 보안 강화 다운로드 기능

3️⃣ Cognito Federated Identities를 이용한 임시 자격 증명 활용
- Cognito에서 발급된 ID 토큰을 기반으로 임시 AWS 자격 증명을 요청하여 S3 접근 제어
