rule The_Basic_One : TheOne{
    meta: 
        Description = "Harmless Malware developed just for experimenting"
        Author = "Dr. Haitham Alani"
    strings:
        $text = "VB6.OLB" 
        $text1 = "Project1.vbp" ascii wide 
        $Path = "Hacked.txt" ascii wide 
        $Scheme = "CaesarCipher" 
        $PATH1 = "http://www.example.com/post_handler" ascii wide
        $EXEC = "updator.exe" ascii wide
        $PATH2 = "application/x-www-form-urlencoded" ascii wide 
        $PATH3 = "https://www.google.com" ascii wide
    condition:
        all of them 
}