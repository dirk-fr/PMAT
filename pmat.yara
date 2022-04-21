
rule malware_unknown {
    meta:
        description = "Detects the Malware.Unknown.exe provided as part of the PMAT course"
        md5 = "812a7c7eb9d7a4332b9e166aa09284d7"
        sha1 = "ec0d565afe635c2c7863b2a05df8a49c58b703a3"
        filename = "Malware.unknown.exe.malz"
        author = "Dirk F."

	Block = true
	Log = true
	Quarantine = false

    strings:
        $malware_user_agent = "httpclient/1.6.2"
        $malware_exfil_file = "Desktop\cosmo.jpeg"
        $malware_kill_switch_url = "hwtwtwpw:w/w/whwewyw.wywowuwuwpw.wlwowcwawlw"
        $malware_exfil_domain = "@.BcBoBsBmBoBsBfBuBrBbBoBoBtBsBeBmBpBoBrBiBuBmB.BlBoBcBaBlB"

    condition:
        IsPeFile and 
        all of ($malware*)