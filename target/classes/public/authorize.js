window.onload = function () {

    var approveBtn = document.getElementById("approve-btn");

    approveBtn.addEventListener("click", () => {

        var username = document.getElementById("username").value;

        var password = document.getElementById("password").value;

        var authorizationValue = btoa(username + ":" + password)

        var content = {
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + authorizationValue
            }
        }

        fetch("/approve", content).then(res =>{

if(res.status===401){
approveBtn.classList.add("unauthorized")

}
            return res.json()
            }
        ).then(res => {
            window.location.href = res.redirect_uri;
        })

    })
}