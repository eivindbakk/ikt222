# How to run

1. **Go to the project folder**

      ```bash
      cd assignment_3
      ```

2. **Create `.env` from the example and fill values**

    * Copy `.env.example` → `.env`
    * Set: `SECRET_KEY`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
    * Ensure: `GITHUB_REDIRECT_URI=http://localhost:5000/callback/github`
      (and your GitHub OAuth App uses the same callback URL)
    * You may use your own GitHub OAuth App, or you can use my provided one in the submission.

3. **Create a virtual environment & install deps**

    * **Windows (PowerShell / Git Bash)**

      ```bash
      python -m venv .venv
      .venv\Scripts\activate
      pip install -r requirements.txt
      ```
   
4. **Initialize the database**

   ```bash
   flask --app app.py init-db
   ```

5. **Start the app**

   ```bash
   python app.py
   ```

6. **Open in your browser**

    * [http://localhost:5000](http://localhost:5000)
