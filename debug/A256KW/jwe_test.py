from oic.oic import OpenIDRequest
from oic.utils.keyio import KeyJar

request='eyJhbGciOiAiQTEyOEtXIiwgImVuYyI6ICJBMTI4Q0JDLUhTMjU2In0.KLuBoByxG54JdHz5OBjpMjx_6ivPNi6oanRZ5UN38VzcTHw2ftv6FA.Tysc6pZ_AA_X7j95bRSHiQ.YxG8Kf3GVWXnMfzOo7Hva32eHcaNBgpcT3iPIEWq76SgKNCpdnGSKOSiFtJbvCdpXwfneXIAS3uFktQoyo9x698IHp92bAZD9M31G0GfaWh7oZgcHrBkn_QPBFavEQeTSfbvhYya3Wp2U9DrL9CrT6ytTo7mbx6b9drUpSe2waIGJkugOOFCiqr19zXXFDT1Qc04sCGhRwz_0JYMYI9qGULQ0Ws2zQVlcE_iMoA6cFs.gDd8Ns2fJRj18A6gg4-T4g'

keyjar = KeyJar()
keyjar.add_symmetric("jJFjKcsaygxp",
                     "f75695a7a87acccdef6c7c978d5e782db1b947e0f6990b050f58940b")

OpenIDRequest().from_jwt(request, keyjar=keyjar, sender="jJFjKcsaygxp")