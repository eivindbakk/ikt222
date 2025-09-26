# XSS Social — Demonstration App

This is a small Flask + SQLite web application we created to demonstrate **stored XSS** vulnerabilities and their mitigations. The repository includes two feeds:

* /feed — intentionally vulnerable (DO NOT expose publicly)
* /feed-safe — sanitized and protected with CSP

---

## Run with Docker

Docker must be installed. On Windows, ensure Docker Desktop is running.

Build the image:
docker build -t xss-social .

Run the container:
docker run --rm -p 5000:5000 --name xss-social xss-social

Access in a browser:
[http://localhost:5000/feed](http://localhost:5000/feed) (vulnerable)
[http://localhost:5000/feed-safe](http://localhost:5000/feed-safe) (safe)

Stop/remove the container:
docker stop xss-social

---

## Notes

Only run the vulnerable feed in an isolated, local environment for educational purposes. To reset demo data for testing/grading, issue a POST to /_reset (local use only).
