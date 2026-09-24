


async function checkURL() {
    let url = document.getElementById("url-input").value;
    console.log("Checking URL:", url);

    try {
        const response = await fetch("http://127.0.0.1:5000/check-url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        console.log("Backend responded:", data);
        return data;
    } catch (err) {
        console.error("Error calling backend:", err);
    }
}
