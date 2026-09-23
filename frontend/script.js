


async function checkURL(){
    
    let url=document.getElementById("url-input").value;

    console.log(url);


    const response =await fetch("http://127.0.0.1:5000/check-url",{

        method : "POST",
        headers : {
            contentType : "application/json"

    },
    body : JSON.stringify({url : url})

    
});

const data = await response.json();

console.log("backend responserd",data); 

}
