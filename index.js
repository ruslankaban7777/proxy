const express = require('express');
const cors = require('cors');
const fileUpload = require('express-fileupload');

const app = express();
const port = process.env.PORT || 3000;
const apiKey = "3f5fa2f2b0c6bb931ad2d29d40d3b74104febdd469048fe6a7acdd5ae049373d";

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(fileUpload());

async function getAnalysisResult(analysisId, retries = 10, delay = 5000) {
    for (let i = 0; i < retries; i++) {
        await new Promise(resolve => setTimeout(resolve, delay));
        const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            method: "GET",
            headers: { "x-apikey": apiKey }
        });

        const data = await response.json();
        if (data.data && data.data.attributes.status === "completed") {
            return data.data.attributes.stats;
        }
    }
    return null;
}

app.post('/check-link', async (req, res) => {
    try {
        const { link } = req.body;

        const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": apiKey,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({ url: link })
        });

        const submitData = await submitResponse.json();
        if (!submitData.data || !submitData.data.id) {
            return res.status(500).json({ result: "Ошибка отправки ссылки в VirusTotal." });
        }

        const stats = await getAnalysisResult(submitData.data.id);
        if (!stats) {
            return res.status(500).json({ result: "Ошибка получения анализа. Повторите позже." });
        }

        if (stats.malicious > 0) {
            res.json({ result: `⚠️ ВНИМАНИЕ: Ссылка вредоносная! (${stats.malicious} угроз)` });
        } else {
            res.json({ result: "✅ Ссылка безопасна." });
        }
    } catch (error) {
        console.log("Ошибка при проверке ссылки:", error);
        res.status(500).json({ result: `Ошибка проверки: ${error.message}` });
    }
});

app.listen(port, () => {
    console.log(`Прокси-сервер запущен на http://localhost:${port}`);
});
