#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="1.0.1"

#0升级脚本
update_shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/yuehen7/scripts/main/main.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} tidak dapat menautkan ke Github !" && exit 0
	wget -N --no-check-certificate "https://raw.githubusercontent.com/yuehen7/scripts/main/main.sh" && chmod +x main.sh
	echo -e "Script telah diperbarui ke versi terbaru[ ${sh_new_ver} ] !(Catatan: Karena metode pembaruan adalah dengan langsung menimpa skrip yang sedang berjalan, beberapa kesalahan mungkin akan muncul di bawah ini, abaikan saja)" && exit 0
}

timezone(){
	cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && hwclock -w && echo $(curl -sSL "https://github.com/yuehen7/scripts/raw/main/time") >> ~/.bashrc 
}

bbr(){
	bash <(curl -Lso- https://git.io/kernel.sh)
}

warp(){
  bash <(curl -sSL "https://raw.githubusercontent.com/fscarmen/warp/main/menu.sh")
}

trojan-go(){
  bash <(curl -sSL "https://raw.githubusercontent.com/yuehen7/scripts/main/trojan-go.sh")	
}

sing-box(){
  bash <(curl -sSL "https://raw.githubusercontent.com/yuehen7/scripts/main/sing-box.sh")	
}

media(){
  bash <(curl -L -s https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/check.sh)
}

huicheng(){
	bash <(curl -sSL "https://raw.githubusercontent.com/zhucaidan/mtr_trace/main/mtr_trace.sh")
}

speedTest(){
  bash <(curl -Lso- https://git.io/superspeed_uxh)
}

result=$(id | awk '{print $1}')
if [[ $result != "uid=0(root)" ]]; then
  echo -e "Silakan jalankan skrip sebagai root"
  exit 0
fi

echo && echo -e " 
+-------------------------------------------------------------+
|                       Untuk orang malas                     |                     
|         Satu kunci di tangan cewek bebas khawatir           |
+-------------------------------------------------------------+
 
 ${Green_font_prefix} 0.${Font_color_suffix} Update Skrip
 —————————System—————————
 ${Green_font_prefix} 1.${Font_color_suffix} Ubah ke zona waktu China (sistem 24 jam, mulai ulang untuk diterapkan)
 ${Green_font_prefix} 2.${Font_color_suffix} instal bbr
 ${Green_font_prefix} 3.${Font_color_suffix} instalasi warp
 —————————Proxy—————————
 ${Green_font_prefix} 4.${Font_color_suffix} instal trojan-go
 ${Green_font_prefix} 5.${Font_color_suffix} instal sing-box
 —————————Test————————— 
 ${Green_font_prefix} 6.${Font_color_suffix} tes streaming
 ${Green_font_prefix} 7.${Font_color_suffix} Tes garis backhaul
 ${Green_font_prefix} 8.${Font_color_suffix} Tes kecepatan jaringan 
" && echo

echo
read -e -p " Silakan masukkan angka [0-8]:" num
case "$num" in
	0)
	update_shell
	;;
	1)
	timezone
	;;
	2)
	bbr
	;;
	3)
	warp
	;;
	4)
	trojan-go
	;;
	5)
	sing-box
	;;
  6)
	media
	;;
  7)
	huicheng
	;;
  8)
	speedTest
	;;
	*)
	echo "Masukkan nomor yang benar [0-8]"
	;;
esac
