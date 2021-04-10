window.onload = function () {

    const urlParams = new URLSearchParams(window.location.search);
    const scope = urlParams.get('scope');

    var ul = document.createElement("ul")
    scope.split(" ").forEach(scope => {
        var scopeli = document.createElement("li")
        scopeli.textContent = scope
        ul.appendChild(scopeli)
    })
    if (scope) {
        var container = document.getElementsByClassName("container")[0]
        container.appendChild(ul)
    }

    var approveBtn = document.getElementById("approve-btn");

    approveBtn.addEventListener("click", () => {

        var username = document.getElementById("username").value;

        var password = document.getElementById("password").value;

        var authorizationValue = btoa(username + ":" + password)

        var metaData = {
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + authorizationValue
            }
        }

        fetch("/approve", metaData).then(res =>
            res.json()
        ).then(res => {
            window.location.href = res.redirect_uri;
        })

    })
}