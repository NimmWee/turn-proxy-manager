"""Regenerate the eight original navigation geometries from the pinned Android commit."""
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

root=Path(__file__).resolve().parents[2]
ref="bab60c5fb620cbea2570eeeb5a0697dc355071f4"
icons={"HomeFilled":"home_24px","HomeOutlined":"home_outlined_24px","Logs":"terminal_24px","ShareFilled":"share_24px","ShareOutlined":"share_outlined_24px","SettingsFilled":"settings_24px","SettingsOutlined":"settings_outlined_24px","Add":"add_24px","Play":"play_arrow_24px","Stop":"stop_24px","Servers":"database_24px","App":"mobile_24px","Advanced":"tune_24px","Info":"info_24px","Chevron":"chevron_right_24px","Back":"arrow_back_24px","Paste":"content_paste_24px","Copy":"content_copy_24px","File":"description_24px","Restore":"cloud_download_24px","Host":"host_24px","Check":"check_24px","Connected":"check_circle_24px","Error":"error_24px","Down":"arrow_downward_24px","Up":"arrow_upward_24px","Edit":"edit_24px","Delete":"delete_24px","Link":"link_24px"}
ns="{http://schemas.android.com/apk/res/android}"
rows=['<!-- SPDX-License-Identifier: GPL-3.0-only. Original FreeTurn Android 5.3.4 navigation vectors. -->', '<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">']
for key,name in icons.items():
    raw=subprocess.check_output(['git','-C',str(root/'.references/android'),'show',f'{ref}:app/src/main/res/drawable/{name}.xml'])
    vector=ET.fromstring(raw)
    if vector.get(ns+'viewportWidth')!='960' or vector.get(ns+'viewportHeight')!='960':
        raise SystemExit('Unexpected icon viewport')
    paths=vector.findall('path')
    if len(paths)!=1: raise SystemExit('Review multipath icon before conversion')
    data=paths[0].get(ns+'pathData')
    if not data: raise SystemExit('Missing vector path')
    rule='F0' if paths[0].get(ns+'fillType')=='evenOdd' else 'F1'
    rows.append(f'  <Geometry x:Key="NavIcon.{key}">{rule} {escape(data)}</Geometry>')
rows.append('</ResourceDictionary>')
logo=ET.fromstring(subprocess.check_output(['git','-C',str(root/'.references/android'),'show',f'{ref}:app/src/main/res/drawable/ic_freeturn.xml']))
group=logo.find('group')
if logo.get(ns+'viewportWidth')!='400' or group is None: raise SystemExit('Unexpected logo')
dx=float(group.get(ns+'translateX','0'))*2.4;dy=float(group.get(ns+'translateY','0'))*2.4
rows.insert(-1,f'  <GeometryGroup x:Key="NavIcon.Logo" Transform="2.4,0,0,2.4,{dx},{dy}">'+''.join(f'<PathGeometry Figures="{escape(p.get(ns+"pathData"))}" />' for p in group.findall('path'))+'</GeometryGroup>')
(Path(__file__).with_name('ui')/'NavigationIcons.xaml').write_text('\n'.join(rows)+'\n',encoding='utf-8')
print(f'Imported {len(icons)} Android vectors and original logo')
