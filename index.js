const express = require('express');
const fetch = require('node-fetch');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

const apiKey = "3f5fa2f2b0c6bb931ad2d29d40d3b74104febdd469048fe6a7acdd5ae049373d";

// Проверка ссылки
app.post('/check-link', async (req, res) => {
    const { link } = req.body;

    try {
        const encodedUrl = Buffer.from(link).toString('base64').replace(/=/g, '');
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
            },
        });

        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats;

        if (stats.malicious > 0) {
            res.json({ result: `⚠️ ВНИМАНИЕ: Ссылка признана вредоносной!\nВредность: ${stats.malicious} из ${Object.values(stats).reduce((a, b) => a + b, 0)}.` });
        } else {
            res.json({ result: "✅ Ссылка безопасна." });
        }
    } catch (error) {
        res.status(500).json({ result: `Ошибка проверки: ${error.message}` });
    }
});

// Проверка файла
app.post('/check-file', async (req, res) => {
    const file = req.files.file;

    try {
        const response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': apiKey,
            },
            body: file.data,
        });

        const data = await response.json();
        const fileId = data.data.id;

        // Получаем отчет о файле
        const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${fileId}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
            },
        });

        const reportData = await reportResponse.json();
        const stats = reportData.data.attributes.stats;

        if (stats.malicious > 0) {
            res.json({ result: `⚠️ ВНИМАНИЕ: Файл признан вредоносным!\nВредность: ${stats.malicious} из ${Object.values(stats).reduce((a, b) => a + b, 0)}.` });
        } else {
            res.json({ result: "✅ Файл безопасен." });
        }
    } catch (error) {
        res.status(500).json({ result: `Ошибка проверки файла: ${error.message}` });
    }
});

app.listen(port, () => {
    console.log(`Прокси-сервер запущен на http://localhost:${port}`);
});
