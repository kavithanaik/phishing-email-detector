// ======================================================
// PHISHING EMAIL DETECTOR - JAVASCRIPT
// ======================================================


// ------------------------------------------------------
// ANALYZE EMAIL
// ------------------------------------------------------

async function analyzeEmail() {

    const emailText =
        document.getElementById("emailText").value.trim();

    const resultCard =
        document.getElementById("resultCard");

    const result =
        document.getElementById("result");

    const loading =
        document.getElementById("loading");

    const button =
        document.getElementById("analyzeButton");


    // Check empty email

    if (!emailText) {

        alert("Please enter an email first.");

        return;
    }


    // Show loading

    loading.classList.remove("hidden");

    button.disabled = true;

    resultCard.classList.add("hidden");


    try {

        const response = await fetch("/analyze", {

            method: "POST",

            headers: {

                "Content-Type": "application/json"

            },

            body: JSON.stringify({

                email: emailText

            })

        });


        const data = await response.json();


        if (!response.ok || !data.success) {

            throw new Error(
                data.error || "Unable to analyze email."
            );

        }


        // ----------------------------------------------
        // RESULT
        // ----------------------------------------------

        resultCard.classList.remove("hidden");


        if (data.prediction === "Phishing") {

            result.innerHTML = `
                <div class="danger-result">
                    <span class="result-icon">⚠</span>
                    <div>
                        <h2>PHISHING EMAIL</h2>
                        <p>
                            This email contains patterns
                            associated with phishing.
                        </p>
                    </div>
                </div>
            `;

        } else {

            result.innerHTML = `
                <div class="safe-result">
                    <span class="result-icon">✓</span>
                    <div>
                        <h2>SAFE EMAIL</h2>
                        <p>
                            No strong phishing indicators
                            were detected.
                        </p>
                    </div>
                </div>
            `;
        }


        // ----------------------------------------------
        // PROBABILITIES
        // ----------------------------------------------

        document.getElementById(
            "phishingProbability"
        ).textContent =
            data.phishing_probability + "%";


        document.getElementById(
            "safeProbability"
        ).textContent =
            data.safe_probability + "%";


        // ----------------------------------------------
        // REASONS
        // ----------------------------------------------

        const reasons =
            document.getElementById("reasons");

        reasons.innerHTML = "";


        if (data.reasons.length === 0) {

            reasons.innerHTML =
                "<li>No suspicious indicators found.</li>";

        } else {

            data.reasons.forEach(reason => {

                const li =
                    document.createElement("li");

                li.textContent = reason;

                reasons.appendChild(li);

            });

        }


        // ----------------------------------------------
        // KEYWORDS
        // ----------------------------------------------

        const keywords =
            document.getElementById("keywords");

        keywords.innerHTML = "";


        if (data.suspicious_keywords.length === 0) {

            keywords.innerHTML =
                "<span class='tag safe-tag'>None detected</span>";

        } else {

            data.suspicious_keywords.forEach(keyword => {

                const span =
                    document.createElement("span");

                span.className = "tag danger-tag";

                span.textContent = keyword;

                keywords.appendChild(span);

            });

        }


        // ----------------------------------------------
        // URLS
        // ----------------------------------------------

        const urls =
            document.getElementById("urls");

        urls.innerHTML = "";


        if (data.suspicious_urls.length > 0) {

            data.suspicious_urls.forEach(url => {

                const div =
                    document.createElement("div");

                div.className = "url-item";

                div.textContent = url;

                urls.appendChild(div);

            });

        } else {

            urls.innerHTML =
                "<span class='tag safe-tag'>No suspicious URLs</span>";

        }


    } catch (error) {

        resultCard.classList.remove("hidden");

        result.innerHTML = `
            <div class="error-result">
                <h2>Error</h2>
                <p>${escapeHtml(error.message)}</p>
            </div>
        `;

    } finally {

        loading.classList.add("hidden");

        button.disabled = false;

    }
}


// ------------------------------------------------------
// LOAD MODEL METRICS
// ------------------------------------------------------

async function loadMetrics() {

    try {

        const response =
            await fetch("/metrics");

        const data =
            await response.json();


        if (!data.success) {

            console.error(
                data.error
            );

            return;
        }


        const m = data.metrics;


        // ----------------------------------------------
        // PERFORMANCE
        // ----------------------------------------------

        document.getElementById(
            "accuracy"
        ).textContent =
            m.accuracy + "%";


        document.getElementById(
            "precision"
        ).textContent =
            m.precision + "%";


        document.getElementById(
            "recall"
        ).textContent =
            m.recall + "%";


        document.getElementById(
            "f1"
        ).textContent =
            m.f1 + "%";


        // ----------------------------------------------
        // CONFUSION MATRIX
        // ----------------------------------------------

        const cm =
            m.confusion_matrix;


        document.getElementById(
            "cm00"
        ).textContent =
            cm[0][0];


        document.getElementById(
            "cm01"
        ).textContent =
            cm[0][1];


        document.getElementById(
            "cm10"
        ).textContent =
            cm[1][0];


        document.getElementById(
            "cm11"
        ).textContent =
            cm[1][1];


        // ----------------------------------------------
        // DATASET
        // ----------------------------------------------

        document.getElementById(
            "totalEmails"
        ).textContent =
            m.total_emails;


        document.getElementById(
            "phishingEmails"
        ).textContent =
            m.phishing_count;


        document.getElementById(
            "safeEmails"
        ).textContent =
            m.safe_count;


        document.getElementById(
            "trainingEmails"
        ).textContent =
            m.training_count;


        document.getElementById(
            "testingEmails"
        ).textContent =
            m.testing_count;


    } catch (error) {

        console.error(
            "Metrics loading error:",
            error
        );

    }
}


// ------------------------------------------------------
// HTML ESCAPE
// ------------------------------------------------------

function escapeHtml(text) {

    const div =
        document.createElement("div");

    div.textContent = text;

    return div.innerHTML;
}


// ------------------------------------------------------
// LOAD EVERYTHING
// ------------------------------------------------------

document.addEventListener(
    "DOMContentLoaded",
    function () {

        loadMetrics();

    }
);