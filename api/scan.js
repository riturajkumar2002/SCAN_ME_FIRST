import { IncomingForm } from "formidable";
import fs from "fs";
import 'dotenv/config';

// Disable Vercel's default bodyParser to allow formidable to parse multipart uploads
export const config = {
    api: {
        bodyParser: false,
    },
};

const getApiKey = () => process.env.VIRUSTOTAL_API_KEY;

const getJsonBody = async req => {
    if (req.body && typeof req.body === "object") {
        return req.body;
    }
    if (typeof req.body === "string" && req.body.length > 0) {
        try {
            return JSON.parse(req.body);
        } catch {
            return {};
        }
    }
    return new Promise((resolve, reject) => {
        let body = "";
        req.on("data", chunk => {
            body += chunk;
        });
        req.on("end", () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (err) {
                reject(err);
            }
        });
        req.on("error", reject);
    });
};

const parseMultipart = req => new Promise((resolve, reject) => {
    const form = new IncomingForm({
        maxFileSize: 32 * 1024 * 1024,
        keepExtensions: true,
    });
    form.parse(req, (err, fields, files) => {
        if (err) return reject(err);
        resolve({ fields, files });
    });
});

const fetchWithKey = (url, options = {}) => {
    const apiKey = getApiKey();
    return fetch(url, {
        ...options,
        headers: {
            "x-apikey": apiKey,
            ...(options.headers || {}),
        },
    });
};

const pollAnalysisResults = async analysisId => {
    const maxAttempts = 20;
    let attempts = 0;
    let interval = 2000;

    while (attempts < maxAttempts) {
        const response = await fetchWithKey(`https://www.virustotal.com/api/v3/analyses/${analysisId}`);
        const report = await response.json();

        if (!response.ok) {
            const errMsg = report?.error?.message || "Error fetching analysis from VirusTotal.";
            throw new Error(errMsg);
        }

        const status = report.data?.attributes?.status;

        if (!status) {
            throw new Error("Invalid analysis response from VirusTotal.");
        }

        if (status === "completed") {
            return report;
        }

        if (status === "failed") {
            throw new Error("VirusTotal analysis failed.");
        }

        if (++attempts >= maxAttempts) {
            throw new Error("VirusTotal analysis timed out. Please try again later.");
        }

        await new Promise(resolve => setTimeout(resolve, interval));
        interval = Math.min(interval * 1.5, 8000);
    }

    throw new Error("VirusTotal analysis timed out. Please try again later.");
};

const handleUrlScan = async req => {
    const body = await getJsonBody(req);
    const url = (body.url || "").trim();

    if (!url) {
        throw new Error("URL is required.");
    }

    try {
        new URL(url);
    } catch {
        throw new Error("Please provide a valid URL (e.g. https://example.com).");
    }

    const formData = new URLSearchParams();
    formData.append("url", url);

    const response = await fetchWithKey("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
        },
        body: formData,
    });

    const submitResult = await response.json();

    if (!response.ok) {
        const errMsg = submitResult?.error?.message || "Failed to submit URL to VirusTotal.";
        throw new Error(errMsg);
    }

    const analysisId = submitResult.data?.id;

    if (!analysisId) {
        throw new Error("Failed to submit URL to VirusTotal.");
    }

    return pollAnalysisResults(analysisId);
};

const handleFileScan = async req => {
    const { fields, files } = await parseMultipart(req);
    let file = files?.file;

    if (!file) {
        throw new Error("No file uploaded.");
    }

    // Normalize file object: formidable may return an array for multiple files
    if (Array.isArray(file)) file = file[0];

    const filePath = file?.filepath || file?.path || file?.filePath || file?.tempFilePath;
    const filename = file?.originalFilename || file?.name || file?.newFilename || file?.filename || "upload.bin";
    const mimeType = file?.mimetype || file?.type || "application/octet-stream";

    let fileBlob = null;
    if (filePath && fs.existsSync(filePath)) {
        const buffer = fs.readFileSync(filePath);
        fileBlob = new Blob([buffer], { type: mimeType });
        try {
            fs.unlinkSync(filePath);
        } catch {
            // Ignore cleanup failure
        }
    } else if (file?.buffer) {
        fileBlob = new Blob([file.buffer], { type: mimeType });
    } else if (file?.data) {
        fileBlob = new Blob([file.data], { type: mimeType });
    }

    if (!fileBlob) {
        throw new Error("Uploaded file data is missing or could not be read.");
    }

    if (fileBlob.size > 32 * 1024 * 1024) {
        throw new Error("File size exceeds 32MB limit.");
    }

    const formData = new FormData();
    formData.append("file", fileBlob, filename);

    const response = await fetchWithKey("https://www.virustotal.com/api/v3/files", {
        method: "POST",
        body: formData,
    });

    const uploadResult = await response.json();

    if (!response.ok) {
        const errMsg = uploadResult?.error?.message || "Failed to upload file to VirusTotal.";
        throw new Error(errMsg);
    }

    const analysisId = uploadResult.data?.id;

    if (!analysisId) {
        throw new Error("Failed to upload file to VirusTotal.");
    }

    return pollAnalysisResults(analysisId);
};

export default async function handler(req, res) {
    if (req.method !== "POST") {
        return res.status(405).json({ error: "Method not allowed. Use POST." });
    }

    const apiKey = getApiKey();
    if (!apiKey) {
        return res.status(500).json({ error: "VirusTotal API key is not configured in environment variables (VIRUSTOTAL_API_KEY)." });
    }

    try {
        const contentType = req.headers["content-type"] || "";

        const report = contentType.includes("multipart/form-data")
            ? await handleFileScan(req)
            : await handleUrlScan(req);

        return res.status(200).json({ report });
    } catch (error) {
        return res.status(400).json({ error: error.message || "An unexpected error occurred." });
    }
}
