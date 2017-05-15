Usage:

python detect_doublepulsar_smb_T.py ipFilePath

ipFilePath 是当前脚本目录下的待测IP文件列表目录，待测IP列表文件名以下划线 _ 来分割左右两边，右边为唯一序号，

如 ip_1.txt,文件中放的是单个ip,一行一个。

脚本遍历目录下的所有文件中的ip对SMB漏洞进行后门检测，并把有后门的ip保存在文件中。

脚本默认打开50个线程，大家可以在脚本里自行设置，

源程序参考链接：https://github.com/countercept/doublepulsar-detection-script

