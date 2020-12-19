# Purpose: This snippet of PowerShell is designed to identify if the version of SolarWinds you're running is effected by the recent SolarWinds hack.
#
# How it works: Simple ForEach loop that looks for known infected files via SHA256 file hash related. 
#
# References: 
#        https://www.solarwinds.com/securityadvisory/faq
#        https://us-cert.cisa.gov/ncas/alerts/aa20-352a
#
# Hashes publicly known to contain the malware:
#     -32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
#     -ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6
#     -019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134
#     -ac1b2b89e60707a20e9eb1ca480bc3410ead40643b386d624c5d21b47c02917c
#     -c09040d35630d75dfef0f804f320f8b3d16a481071076918e9b236a321c1ea77
#     -dab758bf98d9b36fa057a66cd0284737abf89857b73ca89280267ee7caf62f3b
#     -eb6fab5a2964c5817fb239a7a5079cabca0a00464fb3e07155f28b0a57a2c0ed
#     -a25cadd48d70f6ea0c4a241d99c5241269e6faccb4054e62d16784640f8e53bc
#     -9bee4af53a8cdd7ecabe5d0c77b6011abe887ac516a5a22ad51a058830403690
#     -bb86f66d11592e3312cd03423b754f7337aeebba9204f54b745ed3821de6252d
#     -ae6694fd12679891d95b427444466f186bcdcc79bc0627b590e0cb40de1928ad
#     -9d6285db647e7eeabdb85b409fad61467de1655098fec2e25aeb7770299e9fee
#     -8dfe613b00d495fb8905bdf6e1317d3e3ac1f63a626032fa2bdad4750887ee8a
#     -143632672dcb6ef324343739636b984f5c52ece0e078cfee7c6cac4a3545403a
#     -cc870c07eeb672ab33b6c2be51b173ad5564af5d98bfc02da02367a9e349a76f
#
# Author: Brandon Lanczak
# Contact: Brandon@Lanczak.com
#
# Notes: 
#     -If your SolarWinds Orion installation is in a drive other than C:\ make sure you adjust the foreach statement accordingly.
#     -Run as an administrator to ensure it can access all files.
#
# Revision: v1.1 | 12-18-2020 @ 22:47 CST
#
# Execution:
[String] $HashToFind = '32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77',
                        'ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6',
                        '019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134',
                        'ac1b2b89e60707a20e9eb1ca480bc3410ead40643b386d624c5d21b47c02917c',
                        'c09040d35630d75dfef0f804f320f8b3d16a481071076918e9b236a321c1ea77',
                        'dab758bf98d9b36fa057a66cd0284737abf89857b73ca89280267ee7caf62f3b',
                        'eb6fab5a2964c5817fb239a7a5079cabca0a00464fb3e07155f28b0a57a2c0ed',
                        'a25cadd48d70f6ea0c4a241d99c5241269e6faccb4054e62d16784640f8e53bc',
                        '9bee4af53a8cdd7ecabe5d0c77b6011abe887ac516a5a22ad51a058830403690',
                        'bb86f66d11592e3312cd03423b754f7337aeebba9204f54b745ed3821de6252d',
                        'ae6694fd12679891d95b427444466f186bcdcc79bc0627b590e0cb40de1928ad',
                        '9d6285db647e7eeabdb85b409fad61467de1655098fec2e25aeb7770299e9fee',
                        '8dfe613b00d495fb8905bdf6e1317d3e3ac1f63a626032fa2bdad4750887ee8a',
                        '143632672dcb6ef324343739636b984f5c52ece0e078cfee7c6cac4a3545403a',
                        'cc870c07eeb672ab33b6c2be51b173ad5564af5d98bfc02da02367a9e349a76f'

 
Foreach ($file in Get-ChildItem C:\ -file -Recurse)
{
    If ((Get-FileHash $file.Fullname -Algorithm SHA256).hash -eq $HashToFind)
    {
        Write-Host "Infected file found: $($File.Fullname)"
        }
}
 
pause
