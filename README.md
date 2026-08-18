1. Deploy the `fandom-connect` Docker container.

2. Set three environment variables:

   ```env
   GATEWAY_BASE_URL=https://your-domain.com
   GATEWAY_MASTER_KEY=<32-byte base64 secret>
   GATEWAY_ADMIN_PASSWORD=<16+ character password>
   ```

3. In Google Cloud, create/select a project and enable the Google Ads API:

   - **APIs & Services → Library → Google Ads API → Enable**
   - Choose one authentication method:

     **● Service account (recommended)**

     - **IAM & Admin → Service Accounts → Create**
     - Open it → **Keys → Add key → Create new key → JSON**

     **○ Google OAuth**

     - In the same Google Cloud project, open **Google Auth Platform** and enter the required app name and contact email.
     - Under **Audience**, choose **Internal** when the project and authorizing user belong to the same Google Workspace or Cloud Identity organization. Otherwise choose **External**, add the authorizing account as a test user while testing, and complete any Google verification required before production.
     - Under **Data Access**, add `https://www.googleapis.com/auth/adwords`.
     - Under **Clients**, create a **Web application** OAuth client.
     - Add `https://your-domain.com/admin/google/callback` as an authorized redirect URI.
     - Copy the client ID and client secret.

4. In Google Ads:

   - For a service account: **Admin → Access and security → Users → +**, add the service-account email from the JSON file, and choose **Standard** access.
   - For Google OAuth: make sure the Google user who will authorize Fandom Connect has **Standard** access to the intended manager or advertiser account.
   - From a manager account, copy the developer token under **Admin → API Center**.

5. Open `https://your-domain.com/admin` and sign in with your admin password:

   - For a service account: open **Google service account**, then paste the JSON, developer token, and Google Ads account ID.
   - For Google OAuth: open **Google OAuth**, then enter the client ID, client secret, developer token, and Google Ads account ID. Click **Save OAuth settings**, then **Authorize with Google**.
   - Click **Discover accounts and campaigns**.

6. Select the campaigns Fandom may read/write. Enable campaign creation only if wanted. Save.

7. Generate a connection key. In Fandom, open **Integrations → Google Ads → Connect gateway**, then paste the gateway URL and key.

8. In Fandom, open **Permissions** and grant the connected Google Ads account to each role that should use it.
