window.onload = function(){

const urlParams = new URLSearchParams(window.location.search);
const invalid = urlParams.get('invalid');
if(invalid){
document.getElementById("invalid-warning").innerText = "invalid " + invalid
}


}