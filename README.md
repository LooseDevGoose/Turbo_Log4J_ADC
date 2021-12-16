# Turbo_Log4J_ADC
Toolkit to automate community fixes on the ADC regarding the Log4j vulnerability 
Written by Mick Hilhorst (LooseDevGoose).

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Works with the KIVY(MD) library and the NITRO API.
Code is written in Python, application is a packaged .exe.

Please read all the respective fixes their descriptions before implementing them.
This tool, or the fixes and their respective owner are not liable for any damage caused.
Always backup your ADC before implementing anything.
===========================================================================================================================================


List of mitigations included:

1. Eric Julien & Gunther De Poortere & Mads Petersen's Regex fix v2: https://www.linkedin.com/posts/mads-behrendt-petersen-43049613_log4j-citrixctp-security-activity-6875776323139248128-P_N3 (the v3 is not in place yet).
2. Sebastian Parelius's suggestion to enable IP reputation: creates a globally bound default rule that block malicious IP's. "Alot of malicious traffic is from TOR exit nodes, and brightcloud tags those." - works with Premium licenses only
3. Citrix's own responder policies: https://www.citrix.com/blogs/2021/12/13/guidance-for-reducing-apache-log4j-security-vulnerability-risk-with-citrix-waf/

You can combine these settings if you like.

Got your own hot fix that needs to be automated for community purposes?
Contact me on LinkedIn: https://www.linkedin.com/in/mick-hilhorst/
```diff
+- Download the .EXE below:
```
https://mickhilhorst.com/wp-content/uploads/2021/12/Turbo_Log4j_ADC.zip

