import { IncomingForm } from "formidable";
import fs from "fs";
import { Readable } from "stream";
import FormData from "form-data";
import 'dotenv/config';

const API_KEY = process.env.VIRUSTOTAL_API_KEY;

const getJsonBody = req => new Promise((resolve, reject) => {
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

const parseMultipart = req => new Promise((resolve, reject) => {
    const form = new IncomingForm();
    form.parse(req, (err, fields, files) => {
        if (err) return reject(err);
        resolve({ fields, files });
    });
});

const fetchWithKey = (url, options = {}) => {
    return fetch(url, {
        ...options,
        headers: {
            "x-apikey": API_KEY,
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
        throw new Error("Please provide a valid URL.");
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

    // Support different formidable versions that use either `filepath` or `path`,
    // and also support in-memory uploads (buffer/data) from other parsers.
    const filePath = file?.filepath || file?.path || file?.filePath || file?.tempFilePath;
    const filename = file?.originalFilename || file?.name || file?.newFilename || file?.filename || "upload.bin";

    const size = file?.size || (file?.buffer ? file.buffer.length : (file?.data ? file.data.length : 0));
    if (size > 32 * 1024 * 1024) {
        throw new Error("File size exceeds 32MB limit.");
    }

    let fileStream = null;
    if (filePath) {
        fileStream = fs.createReadStream(filePath);
    } else if (file?.buffer) {
        fileStream = Readable.from(file.buffer);
    } else if (file?.data) {
        fileStream = Readable.from(file.data);
    }

    if (!fileStream) {
        throw new Error("Uploaded file data is missing or not supported.");
    }

    const formData = new FormData();
    formData.append("file", fileStream, {
        filename,
        contentType: file?.mimetype || "application/octet-stream",
    });

    const response = await fetchWithKey("https://www.virustotal.com/api/v3/files", {
        method: "POST",
        body: formData,
        headers: {
            ...formData.getHeaders(),
        },
    });

    const uploadResult = await response.json();
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

    if (!API_KEY) {
        return res.status(500).json({ error: "VirusTotal API key is not configured." });
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
