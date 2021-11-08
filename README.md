# Qbot-Strings-Decrypter
An IDA pro python script to decrypt Qbot malware strings.

Tested and working with Qbot OBAMA111 https://www.malware-traffic-analysis.net/2021/10/07/index.html 


<img src="decrypted_strings.png"
     alt="Markdown Monster icon"
     style="float: left; margin-right: 10px;" />


Before using the script make sure to fix the calling convention of the decryption functions like below.


<img src="before.png"
     alt="Markdown Monster icon"
     width= 500px
     height= auto
     style="float: center; margin-center: 10px;" />



<img src="after.png"
     alt="Markdown Monster icon"
     width= 500px
     height= auto
     style="float: center; margin-center: 10px;" />




All the decrypted string will be placed as comment next to the decrypt string function call.

<img src="diasm.png"
     alt="Markdown Monster icon"
     width= 800px
     height= auto
     style="float: center; margin-center: 10px;" />

