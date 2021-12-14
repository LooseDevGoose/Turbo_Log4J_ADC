# Turbo_Log4J_ADC
Toolkit to automate community fixes on the ADC regarding the Log4j vulnerability 
Written by Mick Hilhorst (LooseDevGoose).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.


Works with the KIVY(MD) library and the NITRO API.
Code is written in Python, application is a packaged .exe.

Please read all the respective fixes their descriptions before implementing them.
This tool, or the fixes and their respective owner are not liable for any damage caused.
Always backup your ADC before implementing anything.
===========================================================================================================================================


List of mitigations included:

1. Eric Julien & Gunther De Poortere & Mads Petersen's Regex fix v2: https://www.linkedin.com/posts/mads-behrendt-petersen-43049613_log4j-citrixctp-security-activity-6875776323139248128-P_N3
2. Sebastian Parelius's suggestion to enable IP reputation: creates a globally bound default rule that block malicious IP's. "Alot of malicious traffic is from TOR exit nodes, and brightcloud tags those." - works with Premium licenses only
3. Citrix's own responder policies: https://mickhilhorst.com/wp-content/uploads/2021/12/Log4j_ADC.zip

You can combine these settings if you like.

Got your own hot fix that needs to be automated for community purposes?
Contact me on LinkedIn: https://www.linkedin.com/in/mick-hilhorst/
```diff
+- Download the .EXE below:
```

https://mickhilhorst.com/wp-content/uploads/2021/12/Turbo_Log4j_ADC1.zip

