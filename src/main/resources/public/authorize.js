window.onload = function () {

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