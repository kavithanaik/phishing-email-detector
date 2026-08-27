document.addEventListener("DOMContentLoaded", () => {

    const emailInput = document.getElementById("emailText");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const clearBtn = document.getElementById("clearBtn");

    const loading = document.getElementById("loading");
    const result = document.getElementById("result");
    const error = document.getElementById("error");


    // -------------------------------------------------------
    // Helper
    // -------------------------------------------------------

    function setText(id, value) {

        const element = document.getElementById(id);

        if (element) {
            element.textContent = value;
        }
    }


    function percent(value) {

        const number = Number(value);

        if (isNaN(number)) {
            return "0.00%";
        }

        return number.toFixed(2) + "%";
    }


    // -------------------------------------------------------
    // Analyze
    // -------------------------------------------------------

    analyzeBtn.addEventListener("click", async () => {

        const email = emailInput.value.trim();

        error.classList.add("hidden");


        if (!email) {

            error.textContent =
                "Please enter an email before analyzing.";

            error.classList.remove("hidden");

            return;
        }


        analyzeBtn.disabled = true;

        loading.classList.remove("hidden");


        try {

            const response = await fetch(
                "/predict",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        email: email
                    })
                }
            );


            const data = await response.json();


            if (!response.ok || !data.success) {

                throw new Error(
                    data.error ||
                    "Prediction failed."
                );
            }


            // ------------------------------------------------
            // Prediction
            // ------------------------------------------------

            setText(
                "prediction",
                data.prediction
            );


            setText(
                "confidence",
                percent(data.confidence)
            );


            // ------------------------------------------------
            // Probability
            // ------------------------------------------------

            setText(
                "phishingProbability",
                percent(
                    data.phishing_probability
                )
            );


            setText(
                "safeProbability",
                percent(
                    data.safe_probability
                )
            );


            // ------------------------------------------------
            // Security
            // ------------------------------------------------

            const security =
                data.security || {};


            setText(
                "urlsFound",
                security.urls_found || 0
            );


            setText(
                "suspiciousUrls",
                security.suspicious_urls || 0
            );


            setText(
                "ipUrls",
                security.ip_urls || 0
            );


            setText(
                "emailLength",
                security.email_length || 0
            );


            setText(
                "avgUrlLength",
                Number(
                    security.avg_url_length || 0
                ).toFixed(1)
            );


            setText(
                "exclamationMarks",
                security.exclamation_marks || 0
            );


            setText(
                "specialCharacters",
                security.special_characters || 0
            );


            setText(
                "digits",
                security.digits || 0
            );


            // ------------------------------------------------
            // URLs
            // ------------------------------------------------

            const urlList =
                document.getElementById("urlList");


            urlList.innerHTML = "";


            const urls =
                security.urls || [];


            if (urls.length === 0) {

                urlList.innerHTML =
                    '<p class="empty-message">' +
                    'No URLs detected in this email.' +
                    '</p>';

            } else {

                urls.forEach(url => {

                    const div =
                        document.createElement("div");

                    div.className =
                        "url-item";

                    div.textContent =
                        url;

                    urlList.appendChild(div);

                });

            }


            // ------------------------------------------------
            // Reasons
            // ------------------------------------------------

            const reasonsList =
                document.getElementById("reasons");


            reasonsList.innerHTML = "";


            const reasons =
                data.reasons || [];


            if (reasons.length === 0) {

                const li =
                    document.createElement("li");

                li.textContent =
                    "No major phishing indicators detected.";

                reasonsList.appendChild(li);

            } else {

                reasons.forEach(reason => {

                    const li =
                        document.createElement("li");

                    li.textContent =
                        reason;

                    reasonsList.appendChild(li);

                });

            }


            // ------------------------------------------------
            // Model metrics
            // ------------------------------------------------

            const metrics =
                data.metrics || {};


            setText(
                "accuracy",
                percent(
                    Number(metrics.accuracy || 0) * 100
                )
            );


            setText(
                "totalEmails",
                metrics.total_emails || 0
            );


            setText(
                "phishingCount",
                metrics.phishing_count || 0
            );


            setText(
                "safeCount",
                metrics.safe_count || 0
            );


            // ------------------------------------------------
            // Confusion Matrix
            // ------------------------------------------------

            const matrix =
                metrics.confusion_matrix;


            if (
                matrix &&
                matrix.length >= 2
            ) {

                setText(
                    "matrix00",
                    matrix[0][0]
                );

                setText(
                    "matrix01",
                    matrix[0][1]
                );

                setText(
                    "matrix10",
                    matrix[1][0]
                );

                setText(
                    "matrix11",
                    matrix[1][1]
                );

            }


            // ------------------------------------------------
            // Show result
            // ------------------------------------------------

            result.classList.remove("hidden");


            result.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });


        } catch (err) {

            console.error(err);


            error.textContent =
                err.message ||
                "Unable to connect to the server.";


            error.classList.remove(
                "hidden"
            );

        } finally {

            loading.classList.add(
                "hidden"
            );

            analyzeBtn.disabled =
                false;

        }

    });


    // -------------------------------------------------------
    // Clear
    // -------------------------------------------------------

    clearBtn.addEventListener(
        "click",
        () => {

            emailInput.value = "";

            result.classList.add(
                "hidden"
            );

            error.classList.add(
                "hidden"
            );

            emailInput.focus();

        }
    );

});