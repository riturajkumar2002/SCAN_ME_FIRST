# SCAN_ME_FIRST

A web-based application for scanning URLs and files using the [VirusTotal API](https://www.virustotal.com/). This tool allows users to check the safety of URLs and files by analyzing them against VirusTotal's extensive database of antivirus engines and threat intelligence.

## Features

- **URL Scanning**: Check if a URL is malicious, suspicious, or safe.
- **File Scanning**: Upload files (up to 32MB) for malware analysis.
- **Interactive UI**: Displays scan results with a progress bar, verdict, and detailed statistics.
- **Full Report**: View detailed analysis from multiple antivirus engines in a modal.
- **Responsive Design**: Works seamlessly on desktop and mobile devices.
- **Modern Styling**: Clean and intuitive interface with Tailwind-inspired CSS.

## Demo

- [Live Demo](#) _(Coming soon!)_

## Prerequisites

- A modern web browser (e.g., Chrome, Firefox, Safari).
- A [VirusTotal API key](https://www.virustotal.com/gui/join-us) if you want URL/file scanning to work.
- No build tools are required for this repository because it is a static frontend.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/riturajkumar2002/SCAN_ME_FIRST.git
   cd SCAN_ME_FIRST
   ```

## Set Up the API Key

- This application now uses a secure Vercel serverless function under `api/scan.js`.
- Add `VIRUSTOTAL_API_KEY` to your Vercel Environment Variables in the project settings.
- Do not commit your real API key to GitHub.

## Run the Application

- Open `index.html` directly in your browser, or use a static file server / VS Code Live Server.
- No `npm install` or Node server is required for this static site.
- To deploy, connect the repository to Vercel and deploy from the root directory.

The application will be served automatically by Vercel after deployment.

## Usage

- **Scan a URL**: Enter a URL (e.g., https://example.com) in the "Scan a URL" input field and click "Scan URL".
- **Scan a File**: Select a file (max 32MB) and click "Scan File" to upload and analyze.
- **View Full Report**: Click "View Full Report" to see detailed engine results.

## Project Structure

- index.html # Main HTML file with the UI
- style.css # CSS styles for the application
- script.js # JavaScript for API calls and UI logic
- README.md # Project documentation

## Technologies Used

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **APIs**: VirusTotal API for security scanning
- **Styling**: Tailwind-inspired design with Google Fonts (Inter)

## Security Considerations

- **API Key Safety**: Never commit your VirusTotal API key to a public repository. Use a backend proxy or environment variables to secure it. Ensure `.env` is listed in `.gitignore`.
- **File Size Limit**: Enforces a 32MB limit for file uploads, per VirusTotal’s free API restrictions.
- **Rate Limits**: The free VirusTotal API has limits (e.g., 4 requests/minute). Consider a paid plan for higher quotas.

## Installation & Setup

1. Clone the repository (see Installation above).
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file (use `.env.example` as a template):
   ```env
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   PORT=3001
   ```
4. Start the application:
   ```bash
   npm start
   ```

## Deployment

- **For hosting services like Render, Railway, or Heroku**:
  1. Push the repository to GitHub
  2. Connect the repository to your hosting platform
  3. Set environment variables in your hosting platform dashboard
  4. Deploy the application

- **For local development**:
  - Use `npm start` to run the Node.js server
  - Access the application at `http://localhost:3001`

### Vercel Deployment

- Use Vercel’s Project Settings to add environment variables securely: go to your project → Settings → Environment Variables and add `VIRUSTOTAL_API_KEY` with the value from your VirusTotal account. Choose the appropriate environment (Production/Preview/Development).
- Alternatively, use the Vercel CLI to add a variable (you will be prompted to paste the secret):

```bash
npm i -g vercel
vercel login
vercel env add VIRUSTOTAL_API_KEY production
```

- Do NOT commit your real API key to the repository. This repo includes `.env.example` as a template; create a local `.env` (ignored by Git) for development only.
- `.env.example` should only contain placeholder values; never paste an actual VirusTotal key into it.

## Contributing

- Fork the repository.
- Create a branch: `git checkout -b feature/your-feature`.
- Commit changes: `git commit -m "Add your feature"`.
- Push to the branch: `git push origin feature/your-feature`.
- Open a pull request.

## Acknowledgments

- VirusTotal for providing the API.
- Google Fonts for the Inter font family.

## Contact

For questions or feedback, email riturajkumar9827@gmail.com or open a GitHub issue.

Happy Scanning! 🔍
