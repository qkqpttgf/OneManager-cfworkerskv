
var THEME = 'https://github.com/qkqpttgf/OneManager-php/raw/master/theme/classic.html';
var OMKV;
var disk = new Object();
var GET;
var POST;
var COOKIE = new Object();
var SERVER = new Object();
var ConfigEnvs = {
    'admin'             : 0b000,
    //'adminloginpage'    : 0b010,
    'autoJumpFirstDisk' : 0b010,
    'background'        : 0b011,
    'backgroundm'       : 0b011,
    'disableShowThumb'  : 0b010,
    //'disableChangeTheme': 0b010,
    'disktag'           : 0b000,
    'hideFunctionalityFile': 0b010,
    //'timezone'          : 0b010,
    'passfile'          : 0b011,
    'sitename'          : 0b011,
    'customScript'      : 0b011,
    'customCss'         : 0b011,
    //'customTheme'       : 0b011,
    //'theme'             : 0b010,
    'dontBasicAuth'     : 0b010,

    'Driver'            : 0b100,
    'client_id'         : 0b100,
    'client_secret'     : 0b101,
    'sharepointSite'    : 0b101,
    'shareurl'          : 0b101,
    //'sharecookie'       : 0b101,
    'shareapiurl'       : 0b101,
    'siteid'            : 0b100,
    'refresh_token'     : 0b100,
    'token_expires'     : 0b100,
    'default_drive_id'  : 0b100,
    'default_sbox_drive_id': 0b100,

    'diskname'          : 0b111,
    //'domain_path'       : 0b111,
    'downloadencrypt'   : 0b110,
    'guestup_path'      : 0b111,
    'domainforproxy'    : 0b111,
    'public_path'       : 0b111,
};
var exts = new Object();
exts['img'] = new Array('ico', 'bmp', 'gif', 'jpg', 'jpeg', 'jpe', 'jfif', 'tif', 'tiff', 'png', 'heic', 'webp');
exts['music'] = new Array('mp3', 'wma', 'flac', 'ape', 'wav', 'ogg', 'm4a');
exts['office'] = new Array('doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx');
exts['txt'] = new Array('txt', 'bat', 'sh', 'php', 'asp', 'js', 'css', 'json', 'html', 'c', 'cpp', 'md', 'py', 'omf');
exts['video'] = new Array('mp4', 'webm', 'mkv', 'mov', 'flv', 'blv', 'avi', 'wmv', 'm3u8', 'rm', 'rmvb');
exts['zip'] = new Array('zip', 'rar', '7z', 'gz', 'tar');

addEventListener('fetch', event => {
  let url=new URL(event.request.url);
  if (url.protocol == 'http:') {
    url.protocol = 'https:'
    event.respondWith( Response.redirect(url.href) )
  } else {
    let response = main(event.request);
    event.respondWith( response );
  }
})
// await NAMESPACE.put(key, value)
// NAMESPACE.get(key)
// NAMESPACE.put(key, value, {expiration: secondsSinceEpoch})
// NAMESPACE.put(key, value, {expirationTtl: secondsFromNow})
// await NAMESPACE.delete(key)
async function main(req) {
  if (OMKV==null) {
    return message('请在Workers的设置中将 变量名称 OMKV 绑到目标KV命名空间。', 'Error', 500);
  }
  let url=new URL(req.url);
  let path = url.pathname;
  let body = await req.text();
  POST = parseBody(body, '&');
  let query = url.search;
  if (query.substr(0,1)=='?') query = query.substr(1,query.length);
  GET = parseBody(query, '&');
  let co = req.headers.get("cookie");
  COOKIE = parseBody(co, '; ');
  SERVER['PHP_SELF'] = path;

  let admin = await getConfig('admin');
  if (admin==null||admin=='') return install();

  SERVER['admin'] = false;
  if (COOKIE['admin']==await md5(admin)) {
    SERVER['admin'] = true;
  } else if (GET['admin']==true) {
    if (POST['password1']==admin) {
      SERVER['admin'] = true;
      return adminlogin('admin', await md5(POST['password1']), path);
    } else {
      return adminlogin();
    }
  }

  if (GET['setup']==true) {
    if (SERVER['admin']==true) return setup();
    else {
      let Location = req.url;
      Location = Location.replace('?setup&', '?');
      Location = Location.replace('&setup', '');
      Location = Location.replace('?setup', '');
      return Response.redirect(Location);
    }
  }

  if (('AddDisk' in GET) && SERVER['admin']==true) {
    disk = await diskObject(GET['AddDisk'], GET['disktag']);
    return disk.AddDisk();
  }

  SERVER['base_path'] = '/';
  SERVER['base_disk_path'] = SERVER['base_path'];
  let files = new Object();
  let disktags = (await getConfig('disktag')).split('|');
    if (disktags.length>1) {
        if (path=='/'||path=='') {
            files['type'] = 'folder';
            files['childcount'] = disktags.length;
            files['showname'] = 'root';
            let list = new Object();
            for (let num in disktags) {
              let disktag = disktags[num];
              let child_tmp = new Object();
                child_tmp['type'] = 'folder';
                child_tmp['name'] = disktag;
                child_tmp['showname'] = await getConfig('diskname', disktag);
                list[disktag] = child_tmp;
            }
            files['list'] = list;
            if ('json' in GET) {
                // return a json
                return output(JSON.stringify(files), 200, {'Content-Type' : 'application/json'});
            }
            if (await getConfig('autoJumpFirstDisk')) return output('', 302, { 'Location' : path_format(SERVER['base_path'] + '/' + disktags[0] + '/') });
        } else {
            SERVER['disktag'] = splitfirst( path_format(path).substr(1), '/' )[0];
            if (!(disktags.indexOf(SERVER['disktag'])>-1)) {
                let tmp = path_format(SERVER['base_path'] + '/' + disktags[0] + '/' + path);
                if (GET.length>0) {
                    tmp += '?';
                    for (k in GET) {
                      let v = GET[k];
                        if (v === true) tmp += k + '&';
                        else tmp += k + '=' + v + '&';
                    }
                    tmp = tmp.substr(0, tmp.length-1);
                }
                return output('Please visit <a href="' + tmp + '">' + tmp + '</a>.', 302, { 'Location' : tmp });
                //return message('<meta http-equiv="refresh" content="2;URL='._SERVER['base_path'].'">Please visit from <a href="'._SERVER['base_path'].'">Home Page</a>.', 'Error', 404);
            }
            path = path.substr(('/' + SERVER['disktag']).length);
            if (SERVER['disktag']!='') SERVER['base_disk_path'] = path_format(SERVER['base_disk_path'] + '/' + SERVER['disktag'] + '/');
        }
    } else SERVER['disktag'] = disktags[0];

    if (files['showname'] == 'root'|| SERVER['disktag']=='') return render(path, files);

  SERVER['list_path'] = await getListpath(SERVER['disktag']);
  if (SERVER['list_path']=='') SERVER['list_path'] = '/';
  let path1 = path_format(SERVER['list_path'] + path_format(path));
  if (path1!='/'&&path1.substr(-1)=='/') path1 = path1.substr(0, path1.length-1);
  //SERVER['is_guestup_path'] = await is_guestup_path(path);
  SERVER['ajax']=0;
  if ('HTTP_X_REQUESTED_WITH' in SERVER) if (SERVER['HTTP_X_REQUESTED_WITH']=='XMLHttpRequest') SERVER['ajax']=1;

/*if (SERVER['ajax']) {
        if ($_GET['action']=='del_upload_cache') {
            // del '.tmp' without login. 无需登录即可删除.tmp后缀文件
            return $drive->del_upload_cache(path);
        }
        if ($_GET['action']=='upbigfile') {
            if (!SERVER['admin']) {
                if (!SERVER['is_guestup_path']) return output('Not_Guest_Upload_Folder', 400);
                if (strpos($_GET['upbigfilename'], '../')!==false) return output('Not_Allow_Cross_Path', 400);
            }
            path1 = path_format(SERVER['list_path'] . path_format(path));
            if (substr(path1, -1)=='/') path1=substr(path1, 0, -1);
            return $drive->bigfileupload(path1);
        }
}*/
    if (SERVER['admin']) {
        let tmp = await adminoperate(path);
        if (tmp['status'] > 0) {
            await savecache('path_' + path1, JSON.parse('{}'), SERVER['disktag'], 0);
            return tmp;
        }
    } else {
        if (SERVER['ajax']) return output('管理操作前先登录',401);
    }
    SERVER['ishidden'] = 0;
    /*SERVER['ishidden'] = passhidden($path);
    if (isset($_GET['thumbnails'])) {
        if (SERVER['ishidden']<4) {
            if (in_array(strtolower(substr($path, strrpos($path, '.') + 1)), $exts['img'])) {
                $path1 = path_format(SERVER['list_path'] . path_format($path));
                if ($path1!='/'&&substr($path1, -1)=='/') $path1=substr($path1, 0, -1);
                $thumb_url = $drive->get_thumbnails_url($path1);
                if ($thumb_url!='') {
                    if ($_GET['location']) {
                        $url = $thumb_url;
                        $domainforproxy = '';
                        $domainforproxy = getConfig('domainforproxy', SERVER['disktag']);
                        if ($domainforproxy!='') {
                            $url = proxy_replace_domain($url, $domainforproxy);
                        }
                        return output('', 302, [ 'Location' => $url ]);
                    } else return output($thumb_url);
                }
                return output('', 404);
            } else return output(json_encode($exts['img']), 400);
        } else return output('', 401);
    }*/

    disk = await diskObject((await getConfig('Driver', SERVER['disktag'])), SERVER['disktag']);
    if (await disk.isfine()) files = await disk.list_files(path1);

    if (JSON.stringify(files)=='{}') return render(path, files);
    if (('type' in files) && (files['type']=='file') && !('preview' in GET)) {
        //return Response.redirect(files['url']);
        return output('', 302, { 'Location' : files['url'] });
    }
    if ('type' in files) return render(path, files);
    else return message(JSON.stringify(files), 'Error', 404);
}

async function diskObject(type, tag) {
  if (type==null||type=='') return null;
  let disk = new Object();
  if (type=='Onedrive') {
    disk = new Onedrive(tag);
    await disk.init(tag);
  }
  if (type=='OnedriveCN') {
    disk = new OnedriveCN(tag);
    await disk.init(tag);
  }
  if (type=='Sharepoint') {
    disk = new Sharepoint(tag);
    await disk.init(tag);
  }
  if (type=='SharepointCN') {
    disk = new SharepointCN(tag);
    await disk.init(tag);
  }
  if (type=='Sharelink') {
    disk = new Sharelink(tag);
    await disk.init(tag);
  }
  return disk;
}

function isCommonEnv(key) {
  if (key in ConfigEnvs) return ConfigEnvs[key]&0b100?false:true;
  return null;
}

function isDiskEnv(key) {
  if (key in ConfigEnvs) return ConfigEnvs[key]&0b100?true:false;
  return null;
}

function isShowedEnv(key) {
  if (key in ConfigEnvs) return ConfigEnvs[key]&0b010?true:false;
  return null;
}

function isBase64Env(key) {
  if (key in ConfigEnvs) return ConfigEnvs[key]&0b001?true:false;
  return null;
}

async function md5(str) {
  let msgUint8 = new TextEncoder().encode(str) // encode as (utf-8) Uint8Array
  let hashBuffer = await crypto.subtle.digest('MD5', msgUint8) // hash the message
  let hashArray = Array.from(new Uint8Array(hashBuffer)) // convert buffer to byte array
  let hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  return hashHex;
}

function adminlogin(name, pass, path) {
  if (name!='' && name!=null && pass!='' && pass!=null) {
    if (path==null||path=='') path = '/';
    return output('<meta charset=utf-8>\n\
    <meta http-equiv="refresh" content="3;URL=' + path + '">\n\
        <meta name=viewport content="width=device-width,initial-scale=1">\n\
        登录成功', 200,  {'Set-Cookie': name + '=' + pass + ';path=' + path + ';', 'Content-Type': 'text/html'});
  } else {
    html = '<body>\n\
    <div>\n\
    <center><h4>输入密码</h4>\n\
    <form action="" method="post" onsubmit="return md5pass(this);">\n\
        <div>\n\
            <input name="password1" type="password"/>\n\
            <input name="timestamp" type="hidden"/>\n\
            <input type="submit" value="登录">\n\
        </div>\n\
    </form>\n\
    </center>\n\
    </div>\n\
</body>\n\
<script>\n\
    function md5pass(f) {\n\
        return true;\n\
        var timestamp = new Date().getTime();\n\
        f.timestamp.value = timestamp;\n\
    }\n\
</script>';
    return message(html, '管理登录', 401);
  }
}

async function adminoperate(path)
{
    let path1 = path_format(SERVER['list_path'] + path_format(path));
    if (path1.substr(-1)=='/') path1 = path1.substr(0, path1.length-1);
    tmpget = GET;
    tmppost = POST;
    let tmparr = new Object();
    tmparr['statusCode'] = 0;
    if ( (('rename_newname' in tmpget)&&tmpget['rename_newname']!=tmpget['rename_oldname'] && tmpget['rename_newname']!='') || (('rename_newname' in tmppost)&&tmppost['rename_newname']!=tmppost['rename_oldname'] && tmppost['rename_newname']!='') ) {
        return output('无管理操作', 423);
        /*if (isset(tmppost['rename_newname'])) $VAR = 'tmppost';
        else $VAR = 'tmpget';
        // rename 重命名
        $file['path'] = path1;
        $file['name'] = ${$VAR}['rename_oldname'];
        $file['id'] = ${$VAR}['rename_fileid'];
        return $drive->Rename($file, ${$VAR}['rename_newname']);*/
    }
    if (('delete_name' in tmpget) || ('delete_name' in tmppost)) {
        return output('无管理操作', 423);
        /*if (isset(tmppost['delete_name'])) $VAR = 'tmppost';
        else $VAR = 'tmpget';
        // delete 删除
        $file['path'] = path1;
        $file['name'] = ${$VAR}['delete_name'];
        $file['id'] = ${$VAR}['delete_fileid'];
        return $drive->Delete($file);*/
    }
    if ( (('encrypt_newpass' in tmpget)&&tmpget['encrypt_newpass']!='') || (('encrypt_newpass' in tmppost)&&tmppost['encrypt_newpass']!='') ) {
        return output('无管理操作', 423);
        /*if (isset(tmppost['operate_action'])) $VAR = 'tmppost';
        else $VAR = 'tmpget';
        // encrypt 加密
        if (getConfig('passfile')=='') return message(getconstStr('SetpassfileBfEncrypt'),'',403);
        if (${$VAR}['encrypt_folder']=='/') ${$VAR}['encrypt_folder']=='';
        $folder['path'] = path_format(path1 . '/' . spurlencode(${$VAR}['encrypt_folder'], '/'));
        $folder['name'] = ${$VAR}['encrypt_folder'];
        $folder['id'] = ${$VAR}['id'];
        return $drive->Encrypt($folder, getConfig('passfile'), ${$VAR}['encrypt_newpass']);*/
    }
    if (('move_folder' in tmpget) || ('move_folder' in tmppost)) {
        return output('无管理操作', 423);
        /*if (isset(tmppost['move_folder'])) $VAR = 'tmppost';
        else $VAR = 'tmpget';
        // move 移动
        $moveable = 1;
        if (path == '/' && ${$VAR}['move_folder'] == '/../') $moveable=0;
        if (${$VAR}['move_folder'] == ${$VAR}['move_name']) $moveable=0;
        if ($moveable) {
            $file['path'] = path1;
            $file['name'] = ${$VAR}['move_name'];
            $file['id'] = ${$VAR}['move_fileid'];
            if (${$VAR}['move_folder'] == '/../') {
                $foldername = path_format('/' . urldecode(path1 . '/'));
                $foldername = substr($foldername, 0, -1);
                $foldername = splitlast($foldername, '/')[0];
            } else $foldername = path_format('/' . urldecode(path1) . '/' . ${$VAR}['move_folder']);
            $folder['path'] = $foldername;
            $folder['name'] = ${$VAR}['move_folder'];
            $folder['id'] = '';
            return $drive->Move($file, $folder);
        } else {
            return output('{"error":"' . getconstStr('CannotMove') . '"}', 403);
        }*/
    }
    if (('copy_name' in tmpget) || ('copy_name' in tmppost)) {
        return output('无管理操作', 423);
        /*if (isset(tmppost['copy_name'])) $VAR = 'tmppost';
        else $VAR = 'tmpget';
        // copy 复制
        $file['path'] = path1;
        $file['name'] = ${$VAR}['copy_name'];
        $file['id'] = ${$VAR}['copy_fileid'];
        return $drive->Copy($file);*/
    }
    if ('editfile' in tmppost) {
        return output('无管理操作', 423);
        /*// edit 编辑
        $file['path'] = path1;
        $file['name'] = '';
        $file['id'] = '';
        return $drive->Edit($file, tmppost['editfile']);*/
    }
    if (('create_name' in tmpget) || ('create_name' in tmppost)) {
        return output('无管理操作', 423);
        /*if (isset(tmppost['create_name'])) $VAR = 'tmppost';
        else $VAR = 'tmpget';
        // create 新建
        $parent['path'] = path1;
        $parent['name'] = '';
        $parent['id'] = ${$VAR}['create_fileid'];
        return $drive->Create($parent, ${$VAR}['create_type'], ${$VAR}['create_name'], ${$VAR}['create_text']);*/
    }
    if ('RefreshCache' in GET) {
        await savecache('path_' + path1 + '/?password', '', SERVER['disktag'], 0);
        await savecache('customTheme', '', '', 0);
        return message('<meta http-equiv="refresh" content="2;URL=./">\n\
        <meta name=viewport content="width=device-width,initial-scale=1">', '刷新缓存', 202);
    }
    return tmparr;
}

function isHideFile(str) {
    return false;
}

async function get_content(path)
{
    let path1 = path_format(SERVER['list_path'] + path_format(path));
    if (path1!='/'&&path1.substr(-1)=='/') path1 = path1.substr(0, path1.length-1);
    let file = await disk.list_files(path1);
    //console.log(file);
    return file;
}

function parseBody(str, sp) {
  let tmp = new Object();
  if (str===null) return tmp;
  let arr = str.split(sp);
  for(j = 0, len = arr.length; j < len; j++) {
    if (arr[j]=='') {
      let a = 1;
    } else if (arr[j].indexOf('=')<1) {
        tmp[arr[j]] = true;
    } else {
      let tmp1 = arr[j].split('=');
      if (tmp1[1]==null||tmp1[1]=='') tmp[tmp1[0]] = '';
      else tmp[decodeURIComponent(tmp1[0])] = decodeURIComponent(tmp1[1].replace(/\+/g, '%20'));
      //else tmp[tmp1[0]] = tmp1[1];
    }
  }
  return tmp;
}

function splitfirst(str, sp) {
  let tmp = new Array();
    let pos = str.indexOf(sp);
    if (pos===-1) {
        tmp[0] = str;
        tmp[1] = '';
    } else if (pos>0) {
        tmp[0] = str.substr(0, pos);
        tmp[1] = str.substr(pos+sp.length);
    } else {
        tmp[0] = '';
        tmp[1] = str.substr(sp.length);
    }
    return tmp;
}

function splitlast(str, sp) {
    let tmp = new Array();
    let pos = str.lastIndexOf(sp);
    if (pos===-1) {
        tmp[0] = str;
        tmp[1] = '';
    } else if (pos>0) {
        tmp[0] = str.substr(0, pos);
        tmp[1] = str.substr(pos+sp.length);
    } else {
        tmp[0] = '';
        tmp[1] = str.substr(sp.length);
    }
    return tmp;
}

function path_format(path) {
  path = '/' + path;
  while (path.indexOf('//')>-1) path = path.replace(/\/\//g, '/');
  return path;
}

function spurlencode(str, sp) {
    str = str.replace(/ /g, '%20');
    let tmp='';
    if (sp!=null) {
        let tmparr = str.split(sp);
        for (let num in tmparr) {
            let str1 = tmparr[num];
            tmp += encodeURIComponent(str1) + sp;
        }
        tmp = tmp.substr(0, tmp.length-sp.length);
    } else {
        tmp = encodeURIComponent(str);
    }
    tmp = tmp.replace(/\%2520/g, '%20');
    tmp = tmp.replace(/\%26amp\%3B/g, '&');
    return tmp;
}

async function getListpath(disktag) {
    let public_path = await getConfig('public_path', disktag);
    return spurlencode(public_path, '/');
}

function message(body, title, status) {
  html = '<title>' + title + '</title>\n\
  <html lang="zh-CN">\n\
  <meta charset=utf-8>\n\
  <meta name=viewport content="width=device-width,initial-scale=1">\n\
  <h1>' + title + '</h1>\n\
  <a href="/">返回首页</a><br>\n\
  <div>' + body + '</div>';
  return output(html, status, {'Content-Type':'text/html'});
}

function output(body, status, headers) {
    //if (headers!=null) 
    headers = new Headers(headers);
    if (headers!=null) {
        let Location = headers.get('Location');
        if (Location!=null) {
            if (Location.substr(0,7)=='http://'||Location.substr(0,8)=='https://') return Response.redirect(Location);
            //if (headers!=null && headers.get('Content-Type')==null) headers.set('Content-Type', '');
        }
    }
    //headers.set('content-type', 'text/html');
  return new Response(body, {
    status: status,
    headers: headers
  });
}

async function install() {
  if (('install0' in GET) && POST['admin']!='') {
    let tmp = new Object();
    tmp['admin'] = POST['admin'];
    await setConfig(tmp);
    return message('<meta http-equiv="refresh" content="3;URL=/">', '成功', 200);
  }
  html = '\n\
  <form action="?install0" method="post">\n\
    设置admin密码\n\
    <input name="admin" type="password" placeholder=""><br>\n\
    <input id="submitbtn" type="submit" value="确认">\n\
  </form>';
  return message(html, '安装', 201);
}

function base64y_encode(str)
{
  if (str===null) return "";
  str = btoa(str);
  while (str.substr(-1)=='=') str=str.substr(0,str.length-1);
  str = str.replace(/\+/g, '-');
  str = str.replace(/\//g, '_');
  return str;
}

function base64y_decode(str)
{
  if (str===null) return "";
  str = str.replace(/\-/g, '+');
  str = str.replace(/_/g, '/');
  while (str.length%4>0) str += '=';
  str = atob(str);
    //if (strpos(str, '%')!==false) str = urldecode(str);
  return str;
}

async function getcache(key, disktag) {
  if (disktag==null) disktag = '';
  let tmp = await OMKV.get('OneManagerCache/' + disktag + '/' + key);
  if (tmp===null) return '';
  else {
      if (tmp.substr(0,14)=='KVObjectCache.') {
          tmp = tmp.substr(14);
          return JSON.parse(tmp);
      } else return tmp;
  }
}

async function savecache(key, value, disktag, ttl) {
  if (disktag==null) disktag = '';
  if (ttl==null) ttl = 3000;
  if (typeof value == 'object') {
      let tmp = JSON.stringify(value);
    value = null;
    value = 'KVObjectCache.' + tmp;
  }
  if (ttl===0||ttl===1) await OMKV.delete('OneManagerCache/' + disktag + '/' + key);
  else await OMKV.put('OneManagerCache/' + disktag + '/' + key, value, {expirationTtl: ttl});
}

async function getConfig(key, disktag) {
    if (key==null||key=='') return '';
  if (isDiskEnv(key)) {
    if (disktag==null||disktag=='') disktag = SERVER['disktag'];
    if (disktag==null||disktag=='') return '';
    let diskstr = await OMKV.get(disktag);
    let disk = JSON.parse(diskstr);
    //if (isBase64Env(key)) return base64y_decode(disk[key]);
    //else 
    if (disk!=null && (key in disk)) return disk[key];
  } else {
    let value = await OMKV.get(key);
    //if (isBase64Env(key)) return base64y_decode(value);
    //else 
    if (value!=null) return value;
  }
  return '';
}

async function setConfig(arr, disktag) {
  if (disktag==null||disktag=='') disktag = SERVER['disktag'];
  let disktags = (await getConfig('disktag')).split('|');
  let a = await getConfig(disktag);
  let diskconfig = new Array();
  if (a!='') diskconfig = JSON.parse(a);
  let tmp = new Object();
  let indisk = 0;
  let operatedisk = 0;
  for (let key in arr) {
    if (isDiskEnv(key)) {
      //if (isBase64Env(key)) diskconfig[key] = base64y_encode(arr[key]);
      //else 
      diskconfig[key] = arr[key];
      indisk = 1;
    } else if (key=='disktag_add') {
      disktags.push(arr[key]);
      operatedisk = 1;
    } else if (key=='disktag_del') {
        let pos = disktags.indexOf(arr[key]);
        if (pos>-1) {
            disktags.splice(pos, 1);
      tmp[arr[key]] = '';
      operatedisk = 1;
        }
    } else if (key=='disktag_copy') {
      newtag = arr[key] + '_' + new Date().getTime();
      tmp[newtag] = await getConfig(arr[key]);
      disktags.push(newtag);
      operatedisk = 1;
    } else if (key=='disktag_rename' || key=='disktag_newname') {
      if (arr['disktag_rename']!=arr['disktag_newname']) operatedisk = 1;
    } else {
      //if (isBase64Env(key)) tmp[key] = base64y_encode(arr[key]);
      //else 
      tmp[key] = arr[key];
    }
  }
  
  if (indisk == 1) {
    let diskconfig_tmp = new Object();
    Object.keys(diskconfig).sort().forEach(function(key) {
      if (diskconfig[key]!=null&&diskconfig[key]!=undefined&&diskconfig[key]!='') diskconfig_tmp[key] = diskconfig[key];
    });
    tmp[disktag] = JSON.stringify(diskconfig_tmp);
  }
  if (operatedisk==1) {
    if (('disktag_newname' in arr) && arr['disktag_newname']!='') {
      tags = new Array();
      for (let num in disktags) {
          let tag = disktags[num];
        if (tag==arr['disktag_rename']) tags.push(arr['disktag_newname']);
        else tags.push(tag);
      }
      tmp['disktag'] = tags.join('|');
      tmp[arr['disktag_newname']] = await getConfig(arr['disktag_rename']);
      tmp[arr['disktag_rename']] = '';
    } else {
      let x = new Set(disktags);
      let x1 = [...x].join('|');
      while (x1.substr(0,1)=='|') x1 = x1.substr(1);
      while (x1.substr(-1)=='|') x1 = x1.substr(0, x1.length-1);
      tmp['disktag'] = x1;
    }
  }
  //console.log(tmp);
  for (let key in tmp) {
    if (tmp[key]=='') {
      await OMKV.delete(key);
    } else {
      await OMKV.put(key, tmp[key]);
    }
  }
  return tmp;
}
function htmlSpecialChars(str)
{
  if (str===null) return "";
  let s = "";
  if (str.length == 0) return "";
  for (let i=0; i<str.length; i++) {
    switch (str.substr(i,1)) {
      case "<": s += "&lt;"; break;
      case ">": s += "&gt;"; break;
      case "&": s += "&amp;"; break;
      case " ":
        if(str.substr(i + 1, 1) == " ") {
          s += " &nbsp;";
          i++;
        } else s += " ";
        break;
      case "\"": s += "&quot;"; break;
      //case "\n": s += "<br>"; break;
      default: s += str.substr(i,1); break;
    }
  }
  return s;
}
function time_format(str)
{
    if (str==null||str=='') return '';
    return str.replace('T', ' ');
    let t = new Date(str);
    //
    /*if (str.indexOf('T')>0) {
        str = str.replace('T', ' ');
        str = str.replace('Z', ' ');
        str += ' UTC';
    }*/
    //return date('Y-m-d H:i:s',strtotime($ISO . " UTC"));
    let tmp = t.getFullYear() + '-' + (t.getMonth()+1) + '-' + t.getDate();
    tmp += ' ' + t.getHours() + ':' + t.getMinutes() + ':' + t.getSeconds();
    return tmp;
}
function size_format(byte)
{
    if (byte==null) return ''
    let i = 0;
    while (byte >= 1024) {
        byte = byte / 1024;
        i++;
        if (i == 3) break;
    }
    let units = new Array('B', 'KB', 'MB', 'GB', 'TB');
    let r;
    if (i==0) r = byte;
    else r = byte.toFixed(2);
    return (r + ' ' + units[i]);
}
async function curl(method, url, data, headers, returnhead) {
  let head = new Headers();
  head.set('content-type', 'application/x-www-form-urlencoded;charset=utf-8;');
  for (let key in headers) {
    head.set(key, headers[key]);
  }
  let res = new Object();
  let tmp;
  if (method=='GET') {
      tmp = await fetch(url,{
        method: method,
    　   //mode: 'cors',跨域请求
    　　headers: head
    　});
  } else {
    tmp = await fetch(url,{
        method: method,
    　   //mode: 'cors',跨域请求
    　　headers: head,
    　　body: data
    　})
  }
  res['stat'] = tmp.status;
    res['body'] = await tmp.text();
    if (returnhead!=null) {
        let r_head = new Headers(tmp.headers);
        let h = new Object();
        let c = r_head.get('Set-Cookie');
        if (c!=null) h['Set-Cookie'] = c;
        let Location = r_head.get('Location');
        if (Location!=null) h['Location'] = Location;
        res['returnhead'] = h;
    }
    return res;
}

async function setup() {
  let title = 'OneManager 设置';
  let html = '';
  if ('submit1' in POST) {
    SERVER['disk_oprating'] = '';
    let tmp = new Object();
    for (let k in POST) {
      if (isShowedEnv(k) || k=='disktag_del' || k=='disktag_add' || k=='disktag_rename' || k=='disktag_copy') {
        tmp[k] = POST[k];
      }
      if (k=='disktag_newname') {
        let tmptag = await getConfig(POST[k]);
                //v = preg_replace('/[^0-9a-zA-Z|_]/i', '', v);
                //f = substr(v, 0, 1);
                //if (strlen(v)==1) v .= '_';
        if (isCommonEnv(POST[k])) {
          return message('不要输入固有变量<br><a href="">返回</a>', 'Error', 201);
        } else /*if (!(('a'<=f && f<='z') || ('A'<=f && f<='Z'))) {
                    return message('<a href="">' . getconstStr('Back') . '</a>', 'Please start with letters', 201);
                } else */
          if (tmptag!='') {
            return message('<a href="">返回</a>', '已有此标签', 201);
        } else {
          tmp[k] = POST[k];
        }
      }
      if (k=='disktag_sort') {
        let td = JSON.parse(POST[k]).join('|');
        let dt = await getConfig('disktag');
        if (td.length===dt.length) tmp['disktag'] = td;
        else return message('Something wrong.', 'Error', 500);
      }
      if (k == 'disk') SERVER['disk_oprating'] = POST[k];
    }
    let res = await setConfig(tmp, SERVER['disk_oprating']);
    //html += JSON.stringify(POST);
    //html += JSON.stringify(tmp);
    html += '成功!<br><a href="">返回</a>';
    //html += JSON.stringify(res);
    title = '设置';
    return message(html, title);
  }
  let env_tmp = new Array();
  Object.keys(ConfigEnvs).sort().forEach(function(key) {
    env_tmp[key] = ConfigEnvs[key];
  });
  ConfigEnvs = env_tmp;
  let preurl = '';
  if ('preview' in GET) {
    preurl = path_format(SERVER['PHP_SELF'] + '?preview');
  } else {
    preurl = path_format(SERVER['PHP_SELF'] + '/');
  }
  html += '\n\
<a href="' + preurl + '">返回</a><br>\n\
<a href="https://github.com/qkqpttgf/OneManager-php">Github</a><br>';

  html += '\n\
<table border=1 width=100%>\n\
    <form name="common" action="" method="post">\n\
        <tr>\n\
            <td colspan="2">平台变量</td>\n\
        </tr>';
  for (let key in ConfigEnvs) if (isCommonEnv(key) && isShowedEnv(key)) {
    html += '\n\
        <tr>\n\
            <td><label>' + key + '</label></td>\n\
            <td width=100%><input type="text" name="' + key + '" value="' + htmlSpecialChars(await getConfig(key)) + '" style="width:100%"></td>\n\
        </tr>';
  }
  html += '\n\
        <tr><td><input type="submit" name="submit1" value="设置"></td></tr>\n\
    </form>\n\
</table><br>';
  let disktags = (await getConfig('disktag')).split('|');
  if (disktags.length>1) {
    html += '\n\
<script src="//cdn.bootcss.com/Sortable/1.8.3/Sortable.js"></script>\n\
<style>\n\
    .sortable-ghost {\n\
        opacity: 0.4;\n\
        background-color: #1748ce;\n\
    }\n\
    #sortdisks td {\n\
        cursor: move;\n\
    }\n\
</style>\n\
<table border=1>\n\
    <form id="sortdisks_form" action="" method="post" style="margin: 0" onsubmit="return dragsort(this);">\n\
    <tr id="sortdisks">\n\
        <input type="hidden" name="disktag_sort" value="">';
    let num = 0;
    for (let key in disktags) {
      let disktag = disktags[key];
      if (disktag!='') {
        num++;
        html += '\n\
        <td>' + disktag + '</td>';
      }
    }
    html += '\n\
    </tr>\n\
    <tr><td colspan="' + num + '">拖动以交换位置<input type="submit" name="submit1" value="确定顺序"></td></tr>\n\
    </form>\n\
</table>\n\
<script>\n\
    var disks=' + JSON.stringify(disktags) + ';\n\
    function change(arr, oldindex, newindex) {\n\
        //console.log(oldindex + "," + newindex);\n\
        tmp=arr.splice(oldindex-1, 1);\n\
        if (oldindex > newindex) {\n\
            tmp1=JSON.parse(JSON.stringify(arr));\n\
            tmp1.splice(newindex-1, arr.length-newindex+1);\n\
            tmp2=JSON.parse(JSON.stringify(arr));\n\
            tmp2.splice(0, newindex-1);\n\
        } else {\n\
            tmp1=JSON.parse(JSON.stringify(arr));\n\
            tmp1.splice(newindex-1, arr.length-newindex+1);\n\
            tmp2=JSON.parse(JSON.stringify(arr));\n\
            tmp2.splice(0, newindex-1);\n\
        }\n\
        arr=tmp1.concat(tmp, tmp2);\n\
        //console.log(arr);\n\
        return arr;\n\
    }\n\
    function dragsort(t) {\n\
        if (t.disktag_sort.value==\'\') {\n\
            alert(\'拖动位置\');\n\
            return false;\n\
        }\n\
        return true;\n\
    }\n\
    Sortable.create(document.getElementById(\'sortdisks\'), {\n\
        animation: 150,\n\
        onEnd: function (evt) { //拖拽完毕之后发生该事件\n\
            //console.log(evt.oldIndex);\n\
            //console.log(evt.newIndex);\n\
            if (evt.oldIndex!=evt.newIndex) {\n\
                disks=change(disks, evt.oldIndex, evt.newIndex);\n\
                document.getElementById(\'sortdisks_form\').disktag_sort.value=JSON.stringify(disks);\n\
            }\n\
        }\n\
    });\n\
</script><br>';
  }
  for (let key in disktags) {
    let disktag = disktags[key];
    if (disktag!='') {
            let disk_tmp = await diskObject(await getConfig('Driver', disktag), disktag);
            //console.log(disk_tmp);
            let diskok;
            if (disk_tmp!=null) diskok = await disk_tmp.isfine();
            else diskok = false;
      html += '\n\
<table border=1 width=100%>\n\
    <tr>\n\
        <td>\n\
            <form action="" method="post" style="margin: 0" onsubmit="return deldiskconfirm(this);">\n\
                <input type="hidden" name="disktag_del" value="' + disktag + '">\n\
                <input type="submit" name="submit1" value="删除此盘">\n\
            </form>\n\
        </td>\n\
        <td>\n\
            <form action="" method="post" style="margin: 0" onsubmit="return renametag(this);">\n\
                <input type="hidden" name="disktag_rename" value="' + disktag + '">\n\
                <input type="text" name="disktag_newname" value="' + disktag + '">\n\
                <input type="submit" name="submit1" value="重命名">\n\
            </form>\n\
            <form action="" method="post" style="margin: 0">\n\
                <input type="hidden" name="disktag_copy" value="' + disktag + '">\n\
                <input type="submit" name="submit1" value="复制此盘">\n\
            </form></td>\n\
    </tr>\n\
    <tr>\n\
        <td>Driver</td>\n\
        <td>' + await getConfig('Driver', disktag);
      if (diskok && disk_tmp.baseclassname=='MS365') html += ' <a href="?AddDisk=' + disk_tmp.classname + '&disktag=' + disktag + '&SelectDrive">切换Onedrive与Sharepoint</a>';
      html += '</td>\n\
    </tr>\n\
    ';
      if (diskok) {
        html += '\n\
    <form name="' + disktag + '" action="" method="post">\n\
        <input type="hidden" name="disk" value="' + disktag + '">';
        for (let key in ConfigEnvs) if (isDiskEnv(key) && isShowedEnv(key)) {
          html += '\n\
        <tr>\n\
            <td><label>' + key + '</label></td>\n\
            <td width=100%><input type="text" name="' + key +'" value="' + await getConfig(key, disktag) + '" style="width:100%"></td>\n\
        </tr>';
        }
        html += '\n\
        <tr><td></td><td><input type="submit" name="submit1" value="设置"></td></tr>\n\
    </form>';
      } else {
        html += '\n\
    <tr>\n\
        <td colspan="2">此盘无法正常工作，重新尝试添加</td>\n\
    </tr>';
      }
      html += '\n\
</table><br>';
    }
  }
  let envs = JSON.stringify(Object.keys(ConfigEnvs));
  html += '\n\
<a id="AddDisk_link" href="?AddDisk=Onedrive">添加盘</a>\n\
<script>\n\
    function deldiskconfirm(t) {\n\
        var msg="删除 ??";\n\
        if (confirm(msg)==true) return true;\n\
        else return false;\n\
    }\n\
    function renametag(t) {\n\
        if (t.disktag_newname.value==\'\') {\n\
            alert(\'输入标签\');\n\
            return false;\n\
        }\n\
        if (t.disktag_newname.value==t.disktag_rename.value) {\n\
            return false;\n\
        }\n\
        envs = [' + envs + '];\n\
        if (envs.indexOf(t.disktag_newname.value)>-1) {\n\
            alert("标签中不要输入程序要用到的变量名");\n\
            return false;\n\
        }\n\
        var reg = /^[a-zA-Z]([_a-zA-Z0-9]{1,20})$/;\n\
        if (!reg.test(t.disktag_newname.value)) {\n\
            alert(\'至少2位字母和数字，以字母开头\');\n\
            return false;\n\
        }\n\
        return true;\n\
    }\n\
    function changedrivetype(d) {\n\
        document.getElementById(\'AddDisk_link\').href="?AddDisk=" + d;\n\
    }\n\
</script>\n\
<br><br>';
    return message(html, title);
}

class MS365 {
  constructor(tag) {
      this.baseclassname = 'MS365';
this.disktag = tag;
this.redirect_uri = 'https://scfonedrive.github.io';
return this;
    return (async () => {
      
      this.classname = 'Onedrive';
      
      
      let client_id = await getConfig('client_id', tag);
      let client_secret = await getConfig('client_secret', tag);
      if (client_id!='' && client_secret!='') {
          this.client_id = client_id;
          this.client_secret = client_secret;
      } else {
          this.client_id = '734ef928-d74c-4555-8d1b-d942fa0a1a41';
          this.client_secret = ':EK[e0/4vQ@mQgma8LmnWb6j4_C1CSIW';
      }
      this.oauth_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/';
      this.api_url = 'https://graph.microsoft.com/v1.0';
      this.scope = 'https://graph.microsoft.com/Files.ReadWrite.All offline_access';
      this.client_secret = encodeURIComponent(this.client_secret);
      this.scope = encodeURIComponent(this.scope);
      this.DownurlStrName = '@microsoft.graph.downloadUrl';
      this.ext_api_url = '/me/drive/root';
      this.access_token = '';
     let res = await this.get_access_token(await getConfig('refresh_token', tag));
      
    })();
  }

  async isfine() {
    if (this.access_token!='') return true;
    return false;
  }

  async list_files(path)
    {
        if (path=='') path = '/';
        let files = await getcache('path_' + path, this.disktag);
        if (files == '') {
            //console.log(path + '无缓存');
            let pos = splitlast(path, '/');
            let parentpath = pos[0];
            if (parentpath=='') parentpath = '/';
            let filename = pos[1];
            let parentfiles = await getcache('path_' + parentpath, this.disktag);
            if (parentfiles!='') {
                if (('children' in parentfiles) && (filename in parentfiles['children']) && (this.DownurlStrName in parentfiles['children'][filename])) {
                    if (exts['txt'].indexOf(splitlast(filename,'.')[1])>-1) {
                        let file = parentfiles['children'][filename];
                        if (!(('content' in file)&&file['content']['stat']==200)) {
                            let content1 = await curl('GET', file[this.DownurlStrName]);
                            //console.log(content1);
                            parentfiles['children'][filename]['content'] = content1;
                            await savecache('path_' + parentpath, parentfiles, this.disktag);
                        }
                    }
                    return this.files_format(parentfiles['children'][filename]);
                }
            }

            let url = this.api_url + this.ext_api_url;
            //console.log(url);
            if (path !== '/') {
                url += ':' + path;
                if (url.substr(-1)=='/') url=url.substr(0, url.length-1);
            }
            url += '?expand=children(select=id,name,size,file,folder,parentReference,lastModifiedDateTime,' + this.DownurlStrName + ')';
            let retry = 0;
            let arr = new Object();
            while (JSON.stringify(arr)=='{}'||(retry<3&&arr.status==0)) {
                arr = await curl('GET', url, '', {'Authorization' : 'Bearer ' + this.access_token}, 1);
                retry++;
            }
            //console.log(arr);
            //echo url . '<br><pre>' . json_encode($arr, JSON_PRETTY_PRINT) . '</pre>';
            if (arr['stat']<500) {
                files = JSON.parse(arr['body']);
                //echo '<pre>' . json_encode(files, JSON_PRETTY_PRINT) . '</pre>';
                if ('folder' in files) {
                    /*if (files['folder']['childCount']>200) {
                        // files num > 200 , then get nextlink
                        let page = ('pagenum' in POST)?POST['pagenum']:1;
                        if (page>1)
                        //if (!(files = getcache('path_1' . path . '_' . $page, this.disktag)))
                        {
                            let children = this.fetch_files_children(path, page);
                            //echo '<pre>' . json_encode($children, JSON_PRETTY_PRINT) . '</pre>';
                            files['children'] = $children['value'];
                            //files['children'] = children_name(files['children']);
                            files['folder']['page'] = $page;
                            //savecache('path_' + path . '_' . $page, files, this.disktag);
                        }
                    } else {*/
                    // files num < 200 , then cache
                        //if (isset(files['children'])) {
                            //files['children'] = children_name(files['children']);
                        //}
                        await savecache('path_' + path, files, this.disktag);
                    /*}*/
                }
                if ('file' in files) {
                    //console.log(path + '是file');
                    if (exts['txt'].indexOf(splitlast(files['name'],'.')[1])>-1) {
                        if (!(('content' in files)&&files['content']['stat']==200)) {
                            let content1 = await curl('GET', files[this.DownurlStrName]);
                            files['content'] = content1;
                            await savecache('path_' + path, files, this.disktag);
                        }
                    }
                }
                if ('error' in files) {
                    files['error']['stat'] = arr.status;
                }
            } else {
                //error_log1(await arr.text());
                files = JSON.parse(await arr.text());
                if ('error' in files) {
                    files['error']['stat'] = arr.status;
                } else {
                    files['error'] = new Object();
                    files['error']['stat'] = 503;
                    files['error']['code'] = 'unknownError';
                    files['error']['message'] = 'unknownError';
                }
                //files = json_decode( '{"unknownError":{ "stat":'.arr.status.',"message":"'.await arr.text().'"}}', true);
                //error_log1(json_encode(files, JSON_PRETTY_PRINT));
            }
        }
        //echo '<pre>' . json_encode(files, JSON_PRETTY_PRINT) . '</pre>';
        //console.log(path);
        //console.log(files);
        return this.files_format(files);
    }

    files_format(files)
    {
        //return files;
        let tmp = new Object();
        if ('file' in files) {
            tmp['type'] = 'file';
            tmp['id'] = files['id'];
            tmp['name'] = files['name'];
            tmp['time'] = files['lastModifiedDateTime'];
            tmp['size'] = files['size'];
            tmp['mime'] = files['file']['mimeType'];
            tmp['url'] = files[this.DownurlStrName];
            tmp['content'] = files['content'];
        } else if ('folder' in files) {
            tmp['type'] = 'folder';
            tmp['id'] = files['id'];
            tmp['name'] = files['name'];
            tmp['time'] = files['lastModifiedDateTime'];
            tmp['size'] = files['size'];
            tmp['childcount'] = files['folder']['childCount'];
            tmp['page'] = files['folder']['page'];
            tmp['list'] = new Object();
            for (let num in files['children']) {
                let file = files['children'][num];
                let filename = file['name'].toLowerCase();
                let file_tmp = new Object();
                if ('file' in file) {
                    file_tmp['type'] = 'file';
                    file_tmp['url'] = file[this.DownurlStrName];
                    file_tmp['mime'] = file['file']['mimeType'];
                } else if ('folder' in files) {
                    file_tmp['type'] = 'folder';
                }
                file_tmp['id'] = file['id'];
                file_tmp['name'] = file['name'];
                file_tmp['time'] = file['lastModifiedDateTime'];
                file_tmp['size'] = file['size'];
                tmp['list'][filename] = file_tmp;
            }
        } else if ('error' in files) {
            return files;
        }
        //console.log(tmp);
        return tmp;
    }

  async AddDisk() {
    let url = path_format(SERVER['PHP_SELF'] + '/');
    if ('Finish' in GET) {
        if (this.access_token == '') {
            let refresh_token = await getConfig('refresh_token', this.disktag);
            if (refresh_token=='') {
                let html = 'No refresh_token config, please AddDisk again or wait minutes.<br>' + this.disktag;
                let title = 'Error';
                return message(html, title, 201);
            }
            let response = await this.get_access_token(refresh_token);
            if (!response) return message('获取A_T失败', 'Error', 500);
        }

        let tmp = new Object();
        if (POST['DriveType']=='Onedrive') {
            if (this.classname=='Sharepoint') tmp['Driver'] = 'Onedrive';
            else if (this.classname=='SharepointCN') tmp['Driver'] = 'OnedriveCN';
            tmp['sharepointSite'] = '';
            tmp['siteid'] = '';
        } else if (POST['DriveType']=='Custom') {
            // sitename计算siteid
            let tmp1 = await this.get_siteid(POST['sharepointSite']);
            if (typeof tmp1 == 'object') return message(tmp1['stat'] + tmp1['body'], 'Get Sharepoint Site ID ' + POST['sharepointSite'], tmp1['stat']);
            let siteid = tmp1;
            //api = this.api_url . '/sites/' . siteid . '/drive/';
            //arr = curl('GET', api, '', [ 'Authorization' => 'Bearer ' . this.access_token ], 1);
            //if (arr['stat']!=200) return message(arr['stat'] . arr['body'], 'Get Sharepoint Drive ID ' . _POST['DriveType'], arr['stat']);
            tmp['siteid'] = siteid;
            tmp['sharepointSite'] = POST['sharepointSite'];
            if (this.classname=='Onedrive') tmp['Driver'] = 'Sharepoint';
            else if (this.classname=='OnedriveCN') tmp['Driver'] = 'SharepointCN';
        } else {
            // 直接是siteid
            tmp['siteid'] = POST['DriveType'];
            tmp['sharepointSite'] = POST['sharepointSiteUrl'];
            if (this.classname=='Onedrive') tmp['Driver'] = 'Sharepoint';
            else if (this.classname=='OnedriveCN') tmp['Driver'] = 'SharepointCN';
        }

        let response = await setConfig(tmp, this.disktag);
        
        let str = '<meta http-equiv="refresh" content="5;URL=/">\n\
        <script>\n\
        var expd = new Date();\n\
        expd.setTime(expd.getTime()+1);\n\
        var expires = "expires="+expd.toGMTString();\n\
        document.cookie=\'disktag=; path=/; \'+expires;\n\
        </script>';
        return message(str, '跳转到首页', 201);
            
    }

        if ('SelectDrive' in GET) {
            if (this.classname=='Sharelink') return message('Can not change to other.', 'Back', 201);
            if (this.access_token == '') {
                let refresh_token = await getConfig('refresh_token', this.disktag);
                if (refresh_token=='') {
                    let html = 'No refresh_token config, please AddDisk again or wait minutes.<br>' + this.disktag;
                    let title = 'Error';
                    return message(html, title, 201);
                }
                let response = await this.get_access_token(refresh_token);
                if (!response) return message('获取A_T失败', 'Error', 500);
            }

            let api = this.api_url + '/sites/root';
            let arr = await curl('GET', api, '', { 'Authorization' : 'Bearer ' + this.access_token });
            let Tenant = (JSON.parse(arr['body']))['webUrl'];

            api = this.api_url + '/me/followedSites';
            arr = await curl('GET', api, '', { 'Authorization' : 'Bearer ' + this.access_token });
            if (!(arr['stat']==200||arr['stat']==403||arr['stat']==400)) return message(arr['stat'] + arr['body'], 'Get followedSites', arr['stat']);
            let sites = JSON.parse(arr['body'])['value'];

            let title = 'Select Driver';
            let html = '\n\
<div>\n\
    <form action="?Finish&disktag=' + GET['disktag'] + '&AddDisk=' + this.classname + '" method="post" onsubmit="return notnull(this);">\n\
        <label><input type="radio" name="DriveType" value="Onedrive" checked>用 Onedrive 空间</label><br>';
            if (sites!=null) for (let k in sites) {
                let v = sites[k];
                html += '\n\
        <label>\n\
            <input type="radio" name="DriveType" value="' + v['id'] + '" onclick="document.getElementById(\'sharepointSiteUrl\').value=\'' + v['webUrl'] + '\';">' + '使用此 Sharepoint: <br><div style="width:100%;margin:0px 35px">webUrl: ' + v['webUrl'] + '<br>siteid: ' + v['id'] + '</div>\n\
        </label>';
            }
            html += '\n\
        <input type="hidden" id="sharepointSiteUrl" name="sharepointSiteUrl" value="">\n\
        <label>\n\
            <input type="radio" name="DriveType" value="Custom" id="Custom">' + '输入其它 Sharepoint:<br>\n\
            <div style="width:100%;margin:0px 35px"><a href="' + Tenant + '/_layouts/15/sharepoint.aspx" target="_blank">创建Sharepoint，输入</a><br>\n\
                <input type="text" name="sharepointSite" style="width:100%;" onclick="document.getElementById(\'Custom\').checked=\'checked\';">\n\
            </div>\n\
        </label><br>\n\
        ';
            html += '\n\
        <input type="submit" value="提交">\n\
    </form>\n\
</div>\n\
<script>\n\
        function notnull(t)\n\
        {\n\
            if (t.DriveType.value==\'\') {\n\
                    alert(\'Select a Disk\');\n\
                    return false;\n\
            }\n\
            if (t.DriveType.value==\'Custom\') {\n\
                if (t.sharepointSite.value==\'\') {\n\
                    alert(\'sharepoint Site Address\');\n\
                    return false;\n\
                }\n\
            }\n\
            return true;\n\
        }\n\
    </script>\n\
    ';
            return message(html, title, 201);
        }

        if (('install2' in GET) && ('code' in GET)) {
            let tmp = await curl('POST', this.oauth_url + 'token', 'client_id=' + this.client_id + '&client_secret=' + this.client_secret + '&grant_type=authorization_code&requested_token_use=on_behalf_of&redirect_uri=' + this.redirect_uri + '&code=' + GET['code']);
            let res = new Object();
            if (tmp['stat']==200) res = JSON.parse(tmp['body']);
            if ('refresh_token' in res) {
                let refresh_token = res['refresh_token'];
                let str = '\n\
        refresh_token :<br>';
                str += '\n\
        <textarea readonly style="width: 95%">' + refresh_token + '</textarea><br><br>\n\
        正在保存 refresh_token\n\
        <script>\n\
            var texta=document.getElementsByTagName(\'textarea\');\n\
            for(i=0;i<texta.length;i++) {\n\
                texta[i].style.height = texta[i].scrollHeight + \'px\';\n\
            }\n\
        </script>';
              this.access_token = res['access_token'];
                let tmptoken = new Object();
                tmptoken['refresh_token'] = refresh_token;
                tmptoken['token_expires'] = new Date().getTime()+7*24*60*60*1000;
                let response = await setConfig(tmptoken, this.disktag);

              await savecache('access_token', res['access_token'], this.disktag, res['expires_in'] - 60);
              str += '\n\
                <meta http-equiv="refresh" content="3;URL=' + url + '?AddDisk=' + this.classname + '&disktag=' + GET['disktag'] + '&SelectDrive">';
              return message(str, '等待 3s', 201);
            }
            return message(tmp['body'], tmp['stat'], tmp['stat']);
        }

        if ('install1' in GET) {
          let disktag = await getConfig('Driver', GET['disktag']);
            if (disktag=='Onedrive' || disktag=='OnedriveCN') {
                return message('\n\
    <a href="" id="a1">跳转到office</a>\n\
    <script>\n\
        url=location.protocol + "//" + location.host + "' + url + '?install2&disktag=' + GET['disktag'] + '&AddDisk=' + disktag + '";\n\
        url="' + this.oauth_url + 'authorize?scope=' + this.scope + '&response_type=code&client_id=' + this.client_id + '&redirect_uri=' + this.redirect_uri + '&state=' + '"+encodeURIComponent(url);\n\
        document.getElementById(\'a1\').href=url;\n\
        //window.open(url,"_blank");\n\
        location.href = url;\n\
    </script>\n\
    ', '等待 1s', 201);
            } else {
                return message('Something error, retry after a few seconds.', 'Retry', 201);
            }
        }

        if ('install0' in GET) {
            if (POST['disktag_add']!=null&&POST['disktag_add']!='') {
                /*POST['disktag_add'] = preg_replace('/[^0-9a-zA-Z|_]/i', '', _POST['disktag_add']);
                f = substr(_POST['disktag_add'], 0, 1);
                if (strlen(_POST['disktag_add'])==1) _POST['disktag_add'] .= '_';
                if (isCommonEnv(_POST['disktag_add'])) {
                    return message('Do not input ' . envs . '<br><button onclick="location.href = location.href;">'.getconstStr('Refresh').'</button>', 'Error', 201);
                } elseif (!(('a'<=f && f<='z') || ('A'<=f && f<='Z'))) {
                    return message('Please start with letters<br><button onclick="location.href = location.href;">'.getconstStr('Refresh').'</button>
                    <script>
                    var expd = new Date();
                    expd.setTime(expd.getTime()+1);
                    var expires = "expires="+expd.toGMTString();
                    document.cookie=\'disktag=; path=/; \'+expires;
                    </script>', 'Error', 201);
                }*/

                let tmp = new Object();
                // clear envs
                for (let env in ConfigEnvs) if (isDiskEnv(env)) tmp[env] = '';

                SERVER['disktag'] = POST['disktag_add'];
                tmp['disktag_add'] = POST['disktag_add'];
                tmp['diskname'] = POST['diskname'];
                tmp['Driver'] = POST['Drive_ver'];
                if (POST['Drive_ver']=='Sharelink') {
                    tmp['shareurl'] = POST['shareurl'];
                } else {
                    if (POST['Drive_ver']=='Onedrive' && POST['NT_Drive_custom']=='on') {
                        tmp['client_id'] = POST['NT_client_id'];
                        tmp['client_secret'] = POST['NT_client_secret'];
                    } else if (POST['Drive_ver']=='OnedriveCN' && POST['CN_Drive_custom']=='on') {
                        tmp['client_id'] = POST['CN_client_id'];
                        tmp['client_secret'] = POST['CN_client_secret'];
                    }
                }
                //console.log(tmp);
                let response = await setConfig(tmp, SERVER['disktag']);
                
                let title = '应该已经写入';
                let html = '等待 3s<meta http-equiv="refresh" content="3;URL=' + url + '?install1&disktag=' + GET['disktag'] + '&AddDisk=' + POST['Drive_ver'] + '">';
                if (POST['Drive_ver']=='Sharelink') html = '等待 3s<meta http-equiv="refresh" content="3;URL=' + url + '">';
                return message(html, title, 201);
            }
        }

        let html = '\n\
<div>\n\
    <form id="form1" action="" method="post" onsubmit="return notnull(this);">\n\
        标签: (';
        let disktags = await getConfig('disktag');
        html += disktags + ')\n\
        <input type="text" name="disktag_add" style="width:100%"><br>\n\
        盘名:\n\
        <input type="text" name="diskname" style="width:100%"><br>\n\
        <br>\n\
        <div>\n\
            <label><input type="radio" name="Drive_ver" value="Onedrive" onclick="document.getElementById(\'NT_custom\').style.display=\'\';document.getElementById(\'CN_custom\').style.display=\'none\';document.getElementById(\'inputshareurl\').style.display=\'none\';">MS: 国际版</label><br>\n\
            <div id="NT_custom" style="display:none;margin:0px 35px">\n\
                <label><input type="checkbox" name="NT_Drive_custom" onclick="document.getElementById(\'NT_secret\').style.display=(this.checked?\'\':\'none\');">用自己的ID SECRET</label><br>\n\
                <div id="NT_secret" style="display:none;margin:10px 35px">\n\
                    <a href="https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps" target="_blank">点击跳转，自行创建</a><br>\n\
                    return_uri(Reply URL):<br>https://scfonedrive.github.io/<br>\n\
                    client_id:<input type="text" name="NT_client_id" style="width:100%" placeholder="a1b2c345-90ab-cdef-ghij-klmnopqrstuv"><br>\n\
                    client_secret:<input type="text" name="NT_client_secret" style="width:100%"><br>\n\
                </div>\n\
            </div><br>\n\
            <label><input type="radio" name="Drive_ver" value="OnedriveCN" onclick="document.getElementById(\'CN_custom\').style.display=\'\';document.getElementById(\'NT_custom\').style.display=\'none\';document.getElementById(\'inputshareurl\').style.display=\'none\';">CN: 世纪互联</label><br>\n\
            <div id="CN_custom" style="display:none;margin:0px 35px">\n\
                <label><input type="checkbox" name="CN_Drive_custom" onclick="document.getElementById(\'CN_secret\').style.display=(this.checked?\'\':\'none\');">用自己的ID SECRET</label><br>\n\
                <div id="CN_secret" style="display:none;margin:10px 35px">\n\
                    <a href="https://portal.azure.cn/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps" target="_blank">点击跳转，自行创建</a><br>\n\
                    return_uri(Reply URL):<br>https://scfonedrive.github.io/<br>\n\
                    client_id:<input type="text" name="CN_client_id" style="width:100%" placeholder="a1b2c345-90ab-cdef-ghij-klmnopqrstuv"><br>\n\
                    client_secret:<input type="text" name="CN_client_secret" style="width:100%"><br>\n\
                </div>\n\
            </div><br>\n\
            <label><input type="radio" name="Drive_ver" value="Sharelink" onclick="document.getElementById(\'CN_custom\').style.display=\'none\';document.getElementById(\'inputshareurl\').style.display=\'\';document.getElementById(\'NT_custom\').style.display=\'none\';">Sharelink: 共享链接（<font color="red">只有国际版能用</font>）</label><br>\n\
            <div id="inputshareurl" style="display:none;margin:0px 35px">\n\
                对文件夹右击共享，所有人可编辑，复制链接填入\n\
                <input type="text" name="shareurl" style="width:100%" placeholder="https://xxxx.sharepoint.com/:f:/g/personal/xxxxxxxx/mmmmmmmmm?e=XXXX"><br>\n\
            </div>\n\
        </div>\n\
        <br>';
        html += '你要明白 scfonedrive.github.io 是github上的静态网站，<br>除非github真的挂掉了，<br>不然，稍后你如果连不上，请检查你的运营商或其它“你懂的”问题！<br>';
        let envs = JSON.stringify(Object.keys(ConfigEnvs));
        html +='\n\
        <input type="submit" value="提交">\n\
    </form>\n\
</div>\n\
    <script>\n\
        function notnull(t)\n\
        {\n\
            if (t.disktag_add.value==\'\') {\n\
                alert(\'输入标签\');\n\
                return false;\n\
            }\n\
            envs = ' + envs + ';\n\
            if (envs.indexOf(t.disktag_add.value)>-1) {\n\
                alert("标签中不要输入程序要用到的变量名");\n\
                return false;\n\
            }\n\
            var reg = /^[a-zA-Z]([_a-zA-Z0-9]{1,20})$/;\n\
            if (!reg.test(t.disktag_add.value)) {\n\
                alert(\'至少2位字母和数字，以字母开头\');\n\
                return false;\n\
            }\n\
            if (t.Drive_ver.value==\'\') {\n\
                    alert(\'Select a Driver\');\n\
                    return false;\n\
            }\n\
            if (t.Drive_ver.value==\'Sharelink\') {\n\
                if (t.shareurl.value==\'\') {\n\
                    alert(\'shareurl\');\n\
                    return false;\n\
                }\n\
            } else {\n\
                if ((t.Drive_ver.value==\'Onedrive\') && t.NT_Drive_custom.checked==true) {\n\
                    if (t.NT_client_secret.value==\'\'||t.NT_client_id.value==\'\') {\n\
                        alert(\'client_id & client_secret\');\n\
                        return false;\n\
                    }\n\
                }\n\
                if ((t.Drive_ver.value==\'OnedriveCN\') && t.CN_Drive_custom.checked==true) {\n\
                    if (t.CN_client_secret.value==\'\'||t.CN_client_id.value==\'\') {\n\
                        alert(\'client_id & client_secret\');\n\
                        return false;\n\
                    }\n\
                }\n\
            }\n\
            document.getElementById("form1").action="?install0&disktag=" + t.disktag_add.value + "&AddDisk=" + t.Drive_ver.value;\n\
            return true;\n\
        }\n\
    </script>';
        return message(html, '选择帐号版本', 201);
  }
  async get_access_token(refresh_token) {
    this.access_token = await getcache('access_token', this.disktag);
    if (this.access_token == '') {
            let p = 0;
            let response = null;
            let res = null;
            while (response==null||(response.status==0&&p<3)) {
                response = await curl('POST', this.oauth_url + 'token', 'client_id=' + this.client_id + '&client_secret=' + this.client_secret + '&grant_type=refresh_token&requested_token_use=on_behalf_of&refresh_token=' + refresh_token );
                p++;
            }
            //console.log(response);
            if (response['stat']==200) {
              res = JSON.parse(response['body']);
            }
            if (res==null||!('access_token' in res)) {
                //error_log1(this.oauth_url . 'token' . '?client_id=' . this.client_id . '&client_secret=' . this.client_secret . '&grant_type=refresh_token&requested_token_use=on_behalf_of&refresh_token=' . substr(refresh_token, 0, 20) . '******' . substr(refresh_token, -20));
                //error_log1('failed to get [' . this.disktag . '] access_token. response' . json_encode(res));
                //response['body'] = json_encode(json_decode(response['body']), JSON_PRETTY_PRINT);
                //response['body'] .= '\nfailed to get [' . this.disktag . '] access_token.';
                //return response;
                return false;
            }
            //tmp = res;
            //tmp['access_token'] = '******';
            //tmp['refresh_token'] = '******';
            //error_log1('[' . this.disktag . '] Get access token:' . json_encode(tmp, JSON_PRETTY_PRINT));
            this.access_token = res['access_token'];
            await savecache('access_token', this.access_token, this.disktag, res['expires_in'] - 300);
            let nt = new Date().getTime();
            let exp = await getConfig('token_expires', this.disktag);
            if (nt>exp) await setConfig({ 'refresh_token' : res['refresh_token'], 'token_expires' : nt+7*24*60*60 }, this.disktag);
            return true;
        }
        return true;
  }
  async get_siteid(sharepointSite)
    {
        while (sharepointSite.substr(-1)=='/') sharepointSite = sharepointSite.substr(0, sharepointSite.length-1);
        let tmp = splitlast(sharepointSite, '/');
        let sharepointname = '';
        if (tmp[1]==decodeURIComponent(tmp[1])) {
            sharepointname = encodeURIComponent(tmp[1]);
        } else {
            sharepointname = tmp[1];
        }
        tmp = splitlast(tmp[0], '/');
        let url = '';
        if (this.classname=='Onedrive') url = 'https://graph.microsoft.com/v1.0/sites/root:/' + tmp[1] + '/' + sharepointname;
        if (this.classname=='OnedriveCN') url = 'https://microsoftgraph.chinacloudapi.cn/v1.0/sites/root:/' + tmp[1] + '/' + sharepointname;

        let i=0;
        let response = null;
        while (response==null || response['stat']!=200&&i<3) {
            response = await curl('GET', url, false, {'Authorization' : 'Bearer ' + this.access_token});
            i++;
        }
        if (response['stat']!=200) {
            //error_log1('failed to get siteid. response' . json_encode($response));
            response['body'] += '\nfailed to get siteid.';
            return response;
        }
        return JSON.parse(response['body'])['id'];
    }
}

class Onedrive extends MS365 {
  constructor(tag) {
      super(tag);
    return this;
  }
    async init(tag) {
        //this.baseclassname = 'MS365';
      this.classname = 'Onedrive';
      //this.disktag = tag;
      //this.redirect_uri = 'https://scfonedrive.github.io';
      let client_id = await getConfig('client_id', tag);
      let client_secret = await getConfig('client_secret', tag);
      if (client_id!='' && client_secret!='') {
          this.client_id = client_id;
          this.client_secret = client_secret;
      } else {
          this.client_id = '734ef928-d74c-4555-8d1b-d942fa0a1a41';
          this.client_secret = ':EK[e0/4vQ@mQgma8LmnWb6j4_C1CSIW';
      }
      this.oauth_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/';
      this.api_url = 'https://graph.microsoft.com/v1.0';
      this.scope = 'https://graph.microsoft.com/Files.ReadWrite.All offline_access';
      this.client_secret = encodeURIComponent(this.client_secret);
      this.scope = encodeURIComponent(this.scope);
      this.DownurlStrName = '@microsoft.graph.downloadUrl';
      this.ext_api_url = '/me/drive/root';
      this.access_token = '';
     let res = await this.get_access_token(await getConfig('refresh_token', tag));
    }
}

class OnedriveCN extends MS365 {
  constructor(tag) {
      super(tag);
    return this;
  }
  async init(tag) {
      //this.baseclassname = 'MS365';
      this.classname = 'OnedriveCN';
      //this.disktag = tag;
      //this.redirect_uri = 'https://scfonedrive.github.io';
      let client_id = await getConfig('client_id', tag);
      let client_secret = await getConfig('client_secret', tag);
      if (client_id!='' && client_secret!='') {
          this.client_id = client_id;
          this.client_secret = client_secret;
      } else {
          this.client_id = '31f3bed5-b9d9-4173-86a4-72c73d278617';
          this.client_secret = 'P5-ZNtFK-tT90J.We_-DcsuB8uV7AfjL8Y';
      }
      this.oauth_url = 'https://login.partner.microsoftonline.cn/common/oauth2/v2.0/';
      this.api_url = 'https://microsoftgraph.chinacloudapi.cn/v1.0';
      this.scope = 'https://microsoftgraph.chinacloudapi.cn/Files.ReadWrite.All offline_access';
      this.client_secret = encodeURIComponent(this.client_secret);
      this.scope = encodeURIComponent(this.scope);
      this.DownurlStrName = '@microsoft.graph.downloadUrl';
      this.ext_api_url = '/me/drive/root';
      this.access_token = '';
     let res = await this.get_access_token(await getConfig('refresh_token', tag));
      return this;
    }
}

class Sharepoint extends MS365 {
  constructor(tag) {
      super(tag);
      return this;
  }
  async init(tag) {
      //this.baseclassname = 'MS365';
      this.classname = 'Sharepoint';
      //this.disktag = tag;
      //this.redirect_uri = 'https://scfonedrive.github.io';
      let client_id = await getConfig('client_id', tag);
      let client_secret = await getConfig('client_secret', tag);
      if (client_id!='' && client_secret!='') {
          this.client_id = client_id;
          this.client_secret = client_secret;
      } else {
          this.client_id = '734ef928-d74c-4555-8d1b-d942fa0a1a41';
          this.client_secret = ':EK[e0/4vQ@mQgma8LmnWb6j4_C1CSIW';
      }
      this.oauth_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/';
      this.api_url = 'https://graph.microsoft.com/v1.0';
      this.scope = 'https://graph.microsoft.com/Files.ReadWrite.All offline_access';
      this.client_secret = encodeURIComponent(this.client_secret);
      this.scope = encodeURIComponent(this.scope);
      this.DownurlStrName = '@microsoft.graph.downloadUrl';
      let siteid = await getConfig('siteid', tag);
      this.ext_api_url = '/sites/' + siteid + '/drive/root';
      this.access_token = '';
     let res = await this.get_access_token(await getConfig('refresh_token', tag));
  }
}

class SharepointCN extends MS365 {
  constructor(tag) {
      super(tag);
      return this;
  }
    async init(tag) {
      //this.baseclassname = 'MS365';
      this.classname = 'SharepointCN';
      //this.disktag = tag;
      //this.redirect_uri = 'https://scfonedrive.github.io';
      let client_id = await getConfig('client_id', tag);
      let client_secret = await getConfig('client_secret', tag);
      if (client_id!='' && client_secret!='') {
          this.client_id = client_id;
          this.client_secret = client_secret;
      } else {
          this.client_id = '31f3bed5-b9d9-4173-86a4-72c73d278617';
          this.client_secret = 'P5-ZNtFK-tT90J.We_-DcsuB8uV7AfjL8Y';
      }
      this.oauth_url = 'https://login.partner.microsoftonline.cn/common/oauth2/v2.0/';
      this.api_url = 'https://microsoftgraph.chinacloudapi.cn/v1.0';
      this.scope = 'https://microsoftgraph.chinacloudapi.cn/Files.ReadWrite.All offline_access';
      this.client_secret = encodeURIComponent(this.client_secret);
      this.scope = encodeURIComponent(this.scope);
      this.DownurlStrName = '@microsoft.graph.downloadUrl';
      let siteid = await getConfig('siteid', tag);
      this.ext_api_url = '/sites/' + siteid + '/drive/root';
      this.access_token = '';
     let res = await this.get_access_token(await getConfig('refresh_token', tag));
  }
}

class Sharelink extends MS365 {
  constructor(tag) {
      super(tag);
      return this;
  }
    async init(tag) {
      //this.baseclassname = 'MS365';
      this.classname = 'SharepointCN';
      //this.disktag = tag;
        //this.redirect_uri = 'https://scfonedrive.github.io';
        this.api_url = await getConfig('shareapiurl', tag);
        this.ext_api_url = '';
        this.DownurlStrName = '@content.downloadUrl';
        this.access_token = '';
        let res = await this.get_access_token(1);
  }
  async get_access_token(refresh_token) {
      this.access_token = await getcache('access_token', this.disktag);
        if (this.access_token == '') {
            let shareurl = await getConfig('shareurl', this.disktag);
            this.sharecookie = await getcache('sharecookie', this.disktag);
            if (this.sharecookie == '') {
                this.sharecookie = await curl('GET', shareurl, false, [], 1)['returnhead']['Set-Cookie'];
                //tmp = curl_request(shareurl, false, [], 1);
                //tmp['body'] .= json_encode(tmp['returnhead'],JSON_PRETTY_PRINT);
                //return tmp;
                //SERVER['sharecookie'] = tmp['returnhead']['Set-Cookie'];
                //if (tmp['stat']==302) $url = tmp['returnhead']['Location'];
                //return curl('GET', $url, [ 'Accept' => 'application/json;odata=verbose', 'Content-Type' => 'application/json;odata=verbose', 'Cookie' => SERVER['sharecookie'] ]);
                await savecache('sharecookie', this.sharecookie, this.disktag);
            }
            let tmp1 = splitlast(shareurl, '/')[0];
            let account = splitlast(tmp1, '/')[1];
            let domain = splitlast(shareurl, '/:')[0];
            let response = await curl('POST', 
                domain + "/personal/" + account + "/_api/web/GetListUsingPath(DecodedUrl=@a1)/RenderListDataAsStream?@a1='" + encodeURIComponent("/personal/" + account + "/Documents") + "'&RootFolder=" + encodeURIComponent("/personal/" + account + "/Documents/") + "&TryNewExperienceSingle=TRUE",
                '{"parameters":{"__metadata":{"type":"SP.RenderListDataParameters"},"RenderOptions":136967,"AllowMultipleValueFilterForTaxonomyFields":true,"AddRequiredFields":true}}',
                { 'Accept' : 'application/json;odata=verbose', 'Content-Type' : 'application/json;odata=verbose', 'origin' : domain, 'Cookie' : this.sharecookie }
            );
            let res = new Object();
            if (response['stat']==200) res = JSON.parse(response['body']);
            this.access_token = splitlast(res['ListSchema']['.driveAccessToken'],'=')[1];
            this.api_url = res['ListSchema']['.driveUrl'] + '/root';
            if (this.access_token == '') {
                //error_log1($domain . "/personal/" . $account . "/_api/web/GetListUsingPath(DecodedUrl=@a1)/RenderListDataAsStream?@a1='" . urlencode("/personal/" . $account . "/Documents") . "'&RootFolder=" . urlencode("/personal/" . $account . "/Documents/") . "&TryNewExperienceSingle=TRUE");
                //error_log1('failed to get share access_token. response' . json_encode($ret));
                //response['body'] = json_encode(json_decode($response['body']), JSON_PRETTY_PRINT);
                response['body'] += '\nfailed to get shareurl access_token.';
                return response;
                //throw new Exception($response['stat'].', failed to get share access_token.'.$response['body']);
            }
            //tmp = $ret;
            //tmp['access_token'] = '******';
            //error_log1('['.this.disktag.'] Get access token:'.json_encode(tmp, JSON_PRETTY_PRINT));
            await savecache('access_token', this.access_token, this.disktag);
            tmp1 = null;
            if (await getConfig('shareapiurl', this.disktag)!=this.api_url) tmp1['shareapiurl'] = this.api_url;
            //if (getConfig('sharecookie', this.disktag)!=this.sharecookie) tmp1['sharecookie'] = this.sharecookie;
            if (tmp1!=null) await setConfig(tmp1);
            return true;
        }
        return true;
  }
}

async function render(path, files) {
  let sitename = await getConfig('sitename');
  if (sitename==='') sitename = 'OneManager';

  if (('list' in files) && ('index.html' in files['list']) && !SERVER['admin']) {
        //$htmlcontent = fetch_files(spurlencode(path_format(urldecode(path) . '/index.html'), '/'))['content'];
        let htmlcontent = (await get_content(spurlencode(path_format(decodeURIComponent(path) + '/index.html'), '/')))['content'];
        return output(htmlcontent['body'], htmlcontent['stat']);
    }
    path = path.replace('%20','%2520');
    path = path.replace('+','%2B');
    path = path_format(decodeURIComponent(path)).replace('&','&amp;',);
    path = path.replace('%20',' ');
    path = path.replace('#','%23');
    let p_path='';
    let pretitle = '';
    if (path !== '/') {
        if (('type' in files) && files['type']=='file') {
            pretitle = files['name'].replace('&','&amp;');
            /*n_path = pretitle;
            tmp = splitlast(splitlast(path,'/')[0],'/');
            if (tmp[1]=='') {
                $p_path = tmp[0];
            } else {
                $p_path = tmp[1];
            }*/
        } else {
            if (path.substr(0, 1)=='/') pretitle = path.substr(1);
            if (pretitle.substr(-1)=='/') pretitle = pretitle.substr(0, pretitle.length-1);
            /*tmp=splitlast($pretitle,'/');
            if (tmp[1]=='') {
                $n_path = tmp[0];
            } else {
                $n_path = tmp[1];
                tmp = splitlast(tmp[0],'/');
                if (tmp[1]=='') {
                    $p_path = tmp[0];
                } else {
                    $p_path = tmp[1];
                }
            }*/
        }
    } else {
      pretitle = '首页';
      n_path = pretitle;
    }

  let authinfo =`
<!--
    OneManager: An index & manager of Onedrive auth by ysun.
    Github: https://github.com/qkqpttgf/OneManager-php
-->`;

  let theme1 = await fetch(THEME);
  let html = await theme1.text();

  let tmp = html.split('<!--IconValuesStart-->');
  html = tmp[0];
  tmp = tmp[1].split('<!--IconValuesEnd-->');
  let IconValues = JSON.parse(tmp[0]);
  html += tmp[1];

  html = html.replace(/<!--constStr@language-->/g, 'zh-CN');
  html = html.replace(/<!--base_path-->/g, SERVER['base_path']);
  tmp = splitfirst(html, '<!--SelectLanguageStart-->');
  html = tmp[0];
  tmp = splitfirst(tmp[1], '<!--SelectLanguageEnd-->');
  html += tmp[1];

  if (files==null||JSON.stringify(files)=='{}'||files=='') {
    while (html.indexOf('<!--IsFileStart-->')!==-1) {
      tmp = splitfirst(html, '<!--IsFileStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--IsFileEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--IsFolderStart-->')!==-1) {
      tmp = splitfirst(html, '<!--IsFolderStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--IsFolderEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--HeadomfStart-->')!==-1) {
      tmp = splitfirst(html, '<!--HeadomfStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--HeadomfEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--HeadmdStart-->')!==-1) {
      tmp = splitfirst(html, '<!--HeadmdStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--HeadmdEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--ReadmemdStart-->')!==-1) {
      tmp = splitfirst(html, '<!--ReadmemdStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--ReadmemdEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--FootomfStart-->')!==-1) {
      tmp = splitfirst(html, '<!--FootomfStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--FootomfEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--ListStart-->')!==-1) {
      tmp = splitfirst(html, '<!--ListStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--ListEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--GuestUploadStart-->')!==-1) {
      tmp = splitfirst(html, '<!--GuestUploadStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--GuestUploadEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--EncryptedStart-->')!==-1) {
      tmp = splitfirst(html, '<!--EncryptedStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--EncryptedEnd-->');
      html += tmp[1];
    }
  }
  if (SERVER['admin']===true) {
    while (html.indexOf('<!--LoginStart-->')!==-1) {
      tmp = splitfirst(html, '<!--LoginStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--LoginEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--GuestStart-->')!==-1) {
      tmp = splitfirst(html, '<!--GuestStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--GuestEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--AdminStart-->')!==-1) {
      html = html.replace(/<!--AdminStart-->/g, '');
      html = html.replace(/<!--AdminEnd-->/g, '');
    }
    html = html.replace(/<!--constStr@Operate-->/g, '管理');
    html = html.replace(/<!--constStr@Create-->/g, '创建');
    html = html.replace(/<!--constStr@Encrypt-->/g, '加密');
    html = html.replace(/<!--constStr@RefreshCache-->/g, '刷新缓存');
    html = html.replace(/<!--constStr@Setup-->/g, '设置');
    html = html.replace(/<!--constStr@Logout-->/g, '登出');
    html = html.replace(/<!--constStr@Rename-->/g, '重命名');
    html = html.replace(/<!--constStr@Submit-->/g, '提交');
    html = html.replace(/<!--constStr@Delete-->/g, '删除');
    html = html.replace(/<!--constStr@Copy-->/g, '复制');
    html = html.replace(/<!--constStr@Move-->/g, '移动');
    html = html.replace(/<!--constStr@Folder-->/g, '目录');
    html = html.replace(/<!--constStr@File-->/g, '文件');
    html = html.replace(/<!--constStr@Name-->/g, '名');
    html = html.replace(/<!--constStr@Content-->/g, '内容');
  } else {
    while (html.indexOf('<!--AdminStart-->')!==-1) {
      tmp = splitfirst(html, '<!--AdminStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--AdminEnd-->');
      html += tmp[1];
    }
    let adminloginpage = await getConfig('adminloginpage');
    if (adminloginpage==null||adminloginpage=='') {
      //while (html.indexOf('<!--LoginStart-->')!==-1) {
        html = html.replace(/<!--LoginStart-->/g, '');
        html = html.replace(/<!--LoginEnd-->/g, '');
      //}
      html = html.replace(/<!--constStr@Login-->/g, '登录');
    } else {
      while (html.indexOf('<!--LoginStart-->')!==-1) {
        tmp = splitfirst(html, '<!--LoginStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--LoginEnd-->');
        html += tmp[1];
      }
    }
    html = html.replace(/<!--GuestStart-->/g, '');
    html = html.replace(/<!--GuestEnd-->/g, '');
  }
  if (SERVER['ishidden']==4) {
            // 加密状态
            if (await getConfig('dontBasicAuth')=='') {
                // use Basic Auth
                return output('Need password.', 401, {'WWW-Authenticate':'Basic realm="Secure Area"'});
            }
    while (html.indexOf('<!--IsFileStart-->')!==-1) {
      tmp = splitfirst(html, '<!--IsFileStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--IsFileEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--IsFolderStart-->')!==-1) {
      tmp = splitfirst(html, '<!--IsFolderStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--IsFolderEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--IsNotHiddenStart-->')!==-1) {
      tmp = splitfirst(html, '<!--IsNotHiddenStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--IsNotHiddenEnd-->');
      html += tmp[1];
    }
    html = html.replace(/<!--EncryptedStart-->/g, '');
    html = html.replace(/<!--EncryptedEnd-->/g, '');
    while (html.indexOf('<!--GuestUploadStart-->')!==-1) {
      tmp = splitfirst(html, '<!--GuestUploadStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--GuestUploadEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--HeadomfStart-->')!==-1) {
      tmp = splitfirst(html, '<!--HeadomfStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--HeadomfEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--HeadmdStart-->')!==-1) {
      tmp = splitfirst(html, '<!--HeadmdStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--HeadmdEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--ReadmemdStart-->')!==-1) {
      tmp = splitfirst(html, '<!--ReadmemdStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--ReadmemdEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--FootomfStart-->')!==-1) {
      tmp = splitfirst(html, '<!--FootomfStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--FootomfEnd-->');
      html += tmp[1];
    }
  } else {
    while (html.indexOf('<!--EncryptedStart-->')!==-1) {
      tmp = splitfirst(html, '<!--EncryptedStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--EncryptedEnd-->');
      html += tmp[1];
    }
    html = html.replace(/<!--IsNotHiddenStart-->/g, '');
    html = html.replace(/<!--IsNotHiddenEnd-->/g, '');
  }
  html = html.replace(/<!--constStr@Download-->/g, '下载');
  if (SERVER['is_guestup_path']===true&&SERVER['admin']!==true) {
    while (html.indexOf('<!--IsFileStart-->')!==-1) {
      tmp = splitfirst(html, '<!--IsFileStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--IsFileEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--IsFolderStart-->')!==-1) {
      tmp = splitfirst(html, '<!--IsFolderStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--IsFolderEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--IsNotHiddenStart-->')!==-1) {
      tmp = splitfirst(html, '<!--IsNotHiddenStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--IsNotHiddenEnd-->');
      html += tmp[1];
    }
    html = html.replace(/<!--GuestUploadStart-->/g, '');
    html = html.replace(/<!--GuestUploadEnd-->/g, '');
  } else {
    while (html.indexOf('<!--GuestUploadStart-->')!==-1) {
      tmp = splitfirst(html, '<!--GuestUploadStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--GuestUploadEnd-->');
      html += tmp[1];
    }
    html = html.replace(/<!--IsNotHiddenStart-->/g, '');
    html = html.replace(/<!--IsNotHiddenEnd-->/g, '');
  }
  if (SERVER['is_guestup_path']==true||( SERVER['admin']==true&&files['type']=='folder' )) {
    html = html.replace(/<!--UploadJsStart-->/g, '');
    html = html.replace(/<!--UploadJsEnd-->/g, '');

    html = html.replace(/<!--OnedriveUploadJsStart-->/g, '');
    html = html.replace(/<!--OnedriveUploadJsEnd-->/g, '');
    while (html.indexOf('<!--AliyundriveUploadJsStart-->')!==-1) {
      tmp = splitfirst(html, '<!--AliyundriveUploadJsStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--AliyundriveUploadJsEnd-->');
      html += tmp[1];
    }

    html = html.replace(/<!--constStr@Calculate-->/g, '计算');
  } else {
    while (html.indexOf('<!--UploadJsStart-->')!==-1) {
      tmp = splitfirst(html, '<!--UploadJsStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--UploadJsEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--OnedriveUploadJsStart-->')!==-1) {
      tmp = splitfirst(html, '<!--OnedriveUploadJsStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--OnedriveUploadJsEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--AliyundriveUploadJsStart-->')!==-1) {
      tmp = splitfirst(html, '<!--AliyundriveUploadJsStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--AliyundriveUploadJsEnd-->');
      html += tmp[1];
    }
  }
  if (files!=null&&files['type']=='file') {
    while (html.indexOf('<!--GuestUploadStart-->')!==-1) {
      tmp = splitfirst(html, '<!--GuestUploadStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--GuestUploadEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--EncryptedStart-->')!==-1) {
      tmp = splitfirst(html, '<!--EncryptedStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--EncryptedEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--IsFolderStart-->')!==-1) {
      tmp = splitfirst(html, '<!--IsFolderStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--IsFolderEnd-->');
      html += tmp[1];
    }
    html = html.replace(/<!--IsFileStart-->/g, '');
    html = html.replace(/<!--IsFileEnd-->/g, '');
    html = html.replace(/<!--FileEncodeUrl-->/g, path_format(SERVER['base_disk_path'] + '/' + path));
           //html = str_replace('<!--FileEncodeUrl-->', str_replace('%2523', '%23', str_replace('%26amp%3B','&amp;',spurlencode(path_format(_SERVER['base_disk_path'] . '/' . path), '/'))), html);
    html = html.replace(/<!--FileUrl-->/g, path_format(SERVER['base_disk_path'] + '/' + path));

            let ext = (splitlast(path, '.')[1]).toLowerCase();
            if (exts['img'].indexOf(ext)>-1) ext = 'img';
            else if (exts['video'].indexOf(ext)>-1) ext = 'video';
            else if (exts['music'].indexOf(ext)>-1) ext = 'music';
            //elseif (in_array(ext, exts['pdf'])) ext = 'pdf';
            else if (ext=='pdf') ext = 'pdf';
            else if (exts['office'].indexOf(ext)>-1) ext = 'office';
            else if (exts['txt'].indexOf(ext)>-1) ext = 'txt';
            else ext = 'Other';
            let previewext = ['img', 'video', 'music', 'pdf', 'office', 'txt', 'Other'];
            //previewext = array_diff(previewext, [ ext ]);
            for (let num in previewext) {
                let ext1 = previewext[num];
                if (ext!=ext1) {
                    while (html.indexOf('<!--Is' + ext1 + 'FileStart-->')!==-1) {
                    tmp = splitfirst(html, '<!--Is' + ext1 + 'FileStart-->');
                    html = tmp[0];
                    tmp = splitfirst(tmp[1], '<!--Is' + ext1 + 'FileEnd-->');
                    html += tmp[1];
                    }
                } else {
                    let startreg = new RegExp('/<!--Is' + ext1 + 'FileStart-->/g')
                    html = html.replace(startreg, '');
                    let endreg = new RegExp('/<!--Is' + ext1 + 'FileEnd-->/g')
                    html = html.replace(endreg, '');
                }
            }
            //while (strpos(html, '<!--FileDownUrl-->')) html = str_replace('<!--FileDownUrl-->', files[_SERVER['DownurlStrName']], html);
            html = html.replace(/<!--FileDownUrl-->/g, path_format(SERVER['base_disk_path'] + '/' + path));
            html = html.replace(/<!--FileEncodeReplaceUrl-->/g, path_format(SERVER['base_disk_path'] + '/' + path));
            html = html.replace(/<!--FileName-->/g, files['name']);
            html = html.replace(/<!--FileEncodeDownUrl-->/g, encodeURIComponent(files['url']));
            html = html.replace(/<!--constStr@ClicktoEdit-->/g, '点击后编辑');
            html = html.replace(/<!--constStr@CancelEdit-->/g, '取消编辑');
            html = html.replace(/<!--constStr@Save-->/g, '保存');
            if (html.indexOf('<!--TxtContent-->')>-1) html = html.replace(/<!--TxtContent-->/g, htmlSpecialChars( (await curl('GET', files['url']))['body'] ) );
            html = html.replace(/<!--constStr@FileNotSupport-->/g, '文件不支持');

  } else if (files!=null&&files['type']=='folder') {
    while (html.indexOf('<!--GuestUploadStart-->')!==-1) {
      tmp = splitfirst(html, '<!--GuestUploadStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--GuestUploadEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--EncryptedStart-->')!==-1) {
      tmp = splitfirst(html, '<!--EncryptedStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--EncryptedEnd-->');
      html += tmp[1];
    }
    while (html.indexOf('<!--IsFileStart-->')!==-1) {
      tmp = splitfirst(html, '<!--IsFileStart-->');
      html = tmp[0];
      tmp = splitfirst(tmp[1], '<!--IsFileEnd-->');
      html += tmp[1];
    }
    html = html.replace(/<!--IsFolderStart-->/g, '');
    html = html.replace(/<!--IsFolderEnd-->/g, '');
    html = html.replace(/<!--constStr@File-->/g, '文件');
    html = html.replace(/<!--constStr@ShowThumbnails-->/g, '缩略图');
    html = html.replace(/<!--constStr@CopyAllDownloadUrl-->/g, '复制下载链接');
    html = html.replace(/<!--constStr@EditTime-->/g, '修改时间');
    html = html.replace(/<!--constStr@Size-->/g, '大小');

    let filenum = 0;
    tmp = splitfirst(html, '<!--FolderListStart-->');
    html = tmp[0];
    tmp = splitfirst(tmp[1], '<!--FolderListEnd-->');
    let FolderList = tmp[0];
    for (let name in files['list']) {
        let file = files['list'][name];
      if (file['type']=='folder') {
        if (SERVER['admin'] || !isHideFile(file['name'])) {
          filenum++;
          let FolderListStr = FolderList.replace(/<!--FileEncodeReplaceUrl-->/g, path_format(SERVER['base_disk_path'] + '/' + path + '/' + file['name']));
          FolderListStr = FolderListStr.replace(/<!--FileId-->/g, file['id']);
          FolderListStr = FolderListStr.replace(/<!--FileEncodeReplaceName-->/g, (('showname' in file)&&file['showname']!='')?file['showname']:file['name']);
          FolderListStr = FolderListStr.replace(/<!--lastModifiedDateTime-->/g, time_format(file['time']));
          FolderListStr = FolderListStr.replace(/<!--size-->/g, size_format(file['size']));
          FolderListStr = FolderListStr.replace(/<!--filenum-->/g, filenum);
          html += FolderListStr;
        }
      }
    }
    html += tmp[1];

    tmp = splitfirst(html, '<!--FileListStart-->');
    html = tmp[0];
    tmp = splitfirst(tmp[1], '<!--FileListEnd-->');
    let FileList = tmp[0];
    for (let name in files['list']) {
        //console.log(FileList);
        let file = files['list'][name];
      if (file['type']=='file') {
        if (SERVER['admin'] || !isHideFile(file['name'])) {
            let ext = (splitlast(file['name'], '.')[1]).toLowerCase();
            filenum++;
          let FileListStr = FileList.replace(/<!--FileEncodeReplaceUrl-->/g, path_format(SERVER['base_disk_path'] + '/' + path + '/' + file['name']));
          FileListStr = FileListStr.replace(/<!--FileId-->/g, file['id']);
            FileListStr = FileListStr.replace(/<!--FileEncodeReplaceName-->/g, file['name'].replace('&','&amp;'));
          FileListStr = FileListStr.replace(/<!--lastModifiedDateTime-->/g, time_format(file['time']));
          FileListStr = FileListStr.replace(/<!--size-->/g, size_format(file['size']));
          FileListStr = FileListStr.replace(/<!--filenum-->/g, filenum);

                        //FileListStr = str_replace('<!--FileEncodeReplaceUrl-->', path_format(_SERVER['base_disk_path'] . '/' . path . '/' . encode_str_replace(file['name'])), FolderList);
            FileListStr = FileListStr.replace(/<!--FileExt-->/g, ext);
            if (exts['music'].indexOf(ext)>-1) FileListStr = FileListStr.replace(/<!--FileExtType-->/g, 'audio');
            else if (exts['video'].indexOf(ext)>-1) FileListStr = FileListStr.replace(/<!--FileExtType-->/g, 'iframe');
            else FileListStr = FileListStr.replace(/<!--FileExtType-->/g, '');
                        //FileListStr = str_replace('<!--FileEncodeReplaceUrl-->', path_format(_SERVER['base_disk_path'] . '/' . path . '/' . str_replace('&','&amp;', file['name'])), FileListStr);
            if (IconValues!=null&&JSON.stringify(IconValues)!='{}') {
                for (let key1 in IconValues) if (FileListStr.indexOf('<!--IconValue-->')>-1) {
                    let value1 = IconValues[key1];
                    if ((key1 in exts)&&(exts[key1].indexOf(ext)>-1)) {
                        FileListStr = FileListStr.replace('<!--IconValue-->', value1);
                    }
                    if (ext==key1) {
                        FileListStr = FileListStr.replace('<!--IconValue-->', value1);
                    }
                    //error_log1('file:'.file['name'].':'.key1);
                }
                if (FileListStr.indexOf('<!--IconValue-->')>-1) FileListStr = FileListStr.replace('<!--IconValue-->', IconValues['default']);
            }
          
          html += FileListStr;
        }
      }
    }
    html += tmp[1];

            while (html.indexOf('<!--maxfilenum-->')>-1) html = html.replace('<!--maxfilenum-->', filenum);

            if (files['childcount']>200) {
                while (html.indexOf('<!--MorePageStart-->')>-1) html = html.replace('<!--MorePageStart-->', '');
                while (html.indexOf('<!--MorePageEnd-->')>-1) html = html.replace('<!--MorePageEnd-->', '');

                let pagenum = files['page'];
                if (pagenum=='') pagenum = 1;
                let maxpage = Math.ceil(files['childcount']/200);

                if (pagenum!=1) {
                    html = html.replace('<!--PrePageStart-->', '');
                    html = html.replace('<!--PrePageEnd-->', '');
                    html = html.replace('<!--constStr@PrePage-->', '上一页');
                    html = html.replace('<!--PrePageNum-->', pagenum-1);
                } else {
                    tmp = splitfirst(html, '<!--PrePageStart-->');
                    html = tmp[0];
                    tmp = splitfirst(tmp[1], '<!--PrePageEnd-->');
                    html += tmp[1];
                }
                //html .= json_encode(files['folder']);
                if (pagenum!=maxpage) {
                    html = html.replace('<!--NextPageStart-->', '');
                    html = html.replace('<!--NextPageEnd-->', '');
                    html = html.replace('<!--constStr@NextPage-->', '下一页');
                    html = html.replace('<!--NextPageNum-->', pagenum+1);
                } else {
                    tmp = splitfirst(html, '<!--NextPageStart-->');
                    html = tmp[0];
                    tmp = splitfirst(tmp[1], '<!--NextPageEnd-->');
                    html += tmp[1];
                }
                tmp = splitfirst(html, '<!--MorePageListNowStart-->');
                html = tmp[0];
                tmp = splitfirst(tmp[1], '<!--MorePageListNowEnd-->');
                let MorePageListNow = tmp[0].replace('<!--PageNum-->', pagenum);
                html += tmp[1];

                tmp = splitfirst(html, '<!--MorePageListStart-->');
                html = tmp[0];
                tmp = splitfirst(tmp[1], '<!--MorePageListEnd-->');
                let MorePageList = tmp[0];
                for (page=1;page<=maxpage;page++) {
                    let MorePageListStr = '';
                    if (page == pagenum) {
                        MorePageListStr = MorePageListNow;
                    } else {
                        MorePageListStr = MorePageList.replace('<!--PageNum-->', page);
                        MorePageListStr = MorePageListStr.replace('<!--PageNum-->', page);
                    }
                    html += MorePageListStr;
                }
                html += tmp[1];

                while (html.indexOf('<!--MaxPageNum-->')>-1) html = html.replace('<!--MaxPageNum-->', maxpage);

            } else {
                while (html.indexOf('<!--MorePageStart-->')>-1) {
                    tmp = splitfirst(html, '<!--MorePageStart-->');
                    html = tmp[0];
                    tmp = splitfirst(tmp[1], '<!--MorePageEnd-->');
                    html += tmp[1];
                }
            }
  }
  let title = pretitle;
  if (SERVER['base_disk_path']!=SERVER['base_path']) {
      let diskname = await getConfig('diskname', SERVER['disktag']);
      if (diskname=='') diskname = SERVER['disktag'];
      title += ' - ' + diskname;
  }
  title += ' - ' + sitename;
  html = html.replace('<!--Title-->', title);

  /*keywords = n_path;
  if (p_path!='') keywords .= ', ' . p_path;
  if (_SERVER['sitename']!='OneManager') keywords .= ', ' . _SERVER['sitename'] . ', OneManager';
  else keywords .= ', OneManager';
  html = str_replace('<!--Keywords-->', keywords, html);

  if (_GET['preview']) {
      description = n_path.', '.getconstStr('Preview');//'Preview of '.
  } elseif (files['type']=='folder') {
      description = n_path.', '.getconstStr('List');//'List of '.n_path.'. ';
  }
  //description .= 'In '._SERVER['sitename'];
  html = str_replace('<!--Description-->', description, html);*/
  
  html = html.replace(/<!--Title-->/g, sitename);
  html = html.replace(/<!--base_disk_path-->/g, SERVER['base_disk_path']);
  html = html.replace(/<!--Path-->/g, path);
  customCss = await getConfig('customCss');
  html = html.replace(/<!--customCss-->/g, customCss!=null?customCss:'');
  customScript = await getConfig('customScript');
  html = html.replace(/<!--customScript-->/g, customScript!=null?customScript:'');
  html = html.replace(/<!--constStr@Home-->/g, '首页');
  html = html.replace(/<!--constStr@Close-->/g, '关闭');
  html = html.replace(/<!--constStr@InputPassword-->/g, '输入密码');
  html = html.replace(/<!--constStr@InputPasswordUWant-->/g, '输入你想要的密码');
  html = html.replace(/<!--constStr@Submit-->/g, '提交');
  html = html.replace(/<!--constStr@Success-->/g, '成功');
  html = html.replace(/<!--constStr@GetUploadLink-->/g, '获取上传链接');
  html = html.replace(/<!--constStr@UpFileTooLarge-->/g, '文件过大');
  html = html.replace(/<!--constStr@UploadStart-->/g, '上传开始');
  html = html.replace(/<!--constStr@UploadStartAt-->/g, '上传开始于');
  html = html.replace(/<!--constStr@LastUpload-->/g, '最终上传');
  html = html.replace(/<!--constStr@ThisTime-->/g, '本次');
  html = html.replace(/<!--constStr@Upload-->/g, '上传');
  html = html.replace(/<!--constStr@AverageSpeed-->/g, '平均速度');
  html = html.replace(/<!--constStr@CurrentSpeed-->/g, '当前速度');
  html = html.replace(/<!--constStr@Expect-->/g, '期望');
  html = html.replace(/<!--constStr@UploadErrorUpAgain-->/g, '上传出错，重新上传');
  html = html.replace(/<!--constStr@EndAt-->/g, '结束于');
  html = html.replace(/<!--constStr@UploadComplete-->/g, '上传结束');
  html = html.replace(/<!--constStr@CopyUrl-->/g, '复制链接');
  html = html.replace(/<!--constStr@UploadFail23-->/g, '上传失败，文件名可能有#');
  html = html.replace(/<!--constStr@GetFileNameFail-->/g, '获取文件名失败');
  html = html.replace(/<!--constStr@UploadFile-->/g, '上传文件');
  html = html.replace(/<!--constStr@UploadFolder-->/g, '上传目录');
  html = html.replace(/<!--constStr@FileSelected-->/g, '选择文件');
  html = html.replace(/<!--IsPreview\?-->/g, GET['preview']==true?'?preview&':'?');

  if (html.indexOf('<!--BackgroundStart-->')!==-1) {
    tmp = splitfirst(html, '<!--BackgroundStart-->');
    html = tmp[0];
    tmp = splitfirst(tmp[1], '<!--BackgroundEnd-->');
    let background = await getConfig('background');
    if (background!='') html += tmp[0].replace('<!--BackgroundUrl-->', background);
    html += tmp[1];
  }
  if (html.indexOf('<!--BackgroundMStart-->')!==-1) {
    tmp = splitfirst(html, '<!--BackgroundMStart-->');
    html = tmp[0];
    tmp = splitfirst(tmp[1], '<!--BackgroundMEnd-->');
    let backgroundm = await getConfig('backgroundm');
    if (backgroundm!='null') html += tmp[0].replace('<!--BackgroundMUrl-->', backgroundm);
    html += tmp[1];
  }
//console.log(SERVER['disktag']);
  let disknamenow = '';
  tmp = splitfirst(html, '<!--MultiDiskAreaStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--MultiDiskAreaEnd-->');
        let disktags = (await getConfig('disktag')).split('|');
        let MultiDiskArea = '';
        let diskname = '';
        if (disktags.length>1) {
            let tmp1 = tmp[1];
            tmp = splitfirst(tmp[0], '<!--MultiDisksStart-->');
            MultiDiskArea = tmp[0];
            tmp = splitfirst(tmp[1], '<!--MultiDisksEnd-->');
            let MultiDisks = tmp[0];
            for (let key in disktags) {
                let disk = disktags[key];
                if (disk!='') {
                diskname = await getConfig('diskname', disk);
                if (diskname=='') diskname = disk;
                if (SERVER['disktag']==disk) disknamenow = diskname;
                let MultiDisksStr = MultiDisks.replace(/<!--MultiDisksUrl-->/g, path_format(SERVER['base_path'] + '/' + disk + '/'));
                MultiDisksStr = MultiDisksStr.replace(/<!--MultiDisksNow-->/g, (SERVER['disktag']==disk?' now':''));
                MultiDisksStr = MultiDisksStr.replace(/<!--MultiDisksName-->/g, diskname);
                MultiDiskArea += MultiDisksStr;
                }
            }
            MultiDiskArea += tmp[1];
            tmp[1] = tmp1;
        }
        html += MultiDiskArea + tmp[1];
        //if (strlen(diskname)>15) diskname = substr(diskname, 0, 12).'...';
        html = html.replace(/<!--DiskNameNow-->/g, disknamenow);


        tmp = splitfirst(html, '<!--PathArrayStart-->');
        html = tmp[0];
        if (tmp[1]!='') {
            tmp = splitfirst(tmp[1], '<!--PathArrayEnd-->');
            let PathArrayStr = tmp[0];
            let tmp_url = SERVER['base_disk_path'];
            let tmp_path = (decodeURIComponent(SERVER['PHP_SELF'])).substr(tmp_url.length).replace(/\&/g, '&amp;');
            while (tmp_path!='') {
                let tmp1 = splitfirst(tmp_path, '/');
                let folder1 = tmp1[0];
                if (folder1!='') {
                    tmp_url += folder1 + '/';
                    let PathArrayStr1 = PathArrayStr.replace('<!--PathArrayLink-->', (folder1==files['name']?'':tmp_url));
                    PathArrayStr1 = PathArrayStr1.replace('<!--PathArrayName-->', folder1);
                    html += PathArrayStr1;
                }
                tmp_path = tmp1[1];
            }
            html += tmp[1];
        }
      tmp = splitfirst(html, '<!--DiskPathArrayStart-->');
        html = tmp[0];
        if (tmp[1]!='') {
            tmp = splitfirst(tmp[1], '<!--DiskPathArrayEnd-->');
            let PathArrayStr = tmp[0];
            let tmp_url = SERVER['base_path'];
            let tmp_path = (decodeURIComponent(SERVER['PHP_SELF'])).substr(tmp_url.length).replace(/\&/g, '&amp;');
            while (tmp_path!='') {
                let tmp1 = splitfirst(tmp_path, '/');
                let folder1 = tmp1[0];
                if (folder1!='') {
                    tmp_url += folder1 + '/';
                    PathArrayStr1 = PathArrayStr.replace('<!--PathArrayLink-->', (folder1==files['name']?'':tmp_url));
                    PathArrayStr1 = PathArrayStr1.replace('<!--PathArrayName-->', (folder1==SERVER['disktag']?(disknamenow==''?SERVER['disktag']:disknamenow):folder1));
                    html += PathArrayStr1;
                }
                tmp_path = tmp1[1];
            }
            html += tmp[1];
        }
  if (html.indexOf('<!--NeedUpdateStart-->')!==-1) {
    tmp = splitfirst(html, '<!--NeedUpdateStart-->');
    html = tmp[0];
    tmp = splitfirst(tmp[1], '<!--NeedUpdateEnd-->');
    html += tmp[1];
  }
    tmp = splitfirst(html, '<!--BackArrowStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--BackArrowEnd-->');
        let current_url = path_format(SERVER['PHP_SELF'] + '/');
        let parent_url = '';
        let BackArrow = '';
        if (current_url !== SERVER['base_path']) {
            while (current_url.substr(-1) === '/') {
                current_url = current_url.substr(0, current_url.length-1);
            }
            if (current_url.indexOf('/')>-1) {
                parent_url = current_url.substr(0, current_url.lastIndexOf('/'));
            } else {
                parent_url = current_url;
            }
            BackArrow = tmp[0].replace('<!--BackArrowUrl-->', parent_url + '/');
        }
        html += BackArrow + tmp[1];

        while (html.indexOf('<!--ShowThumbnailsStart-->')!==-1) {
            tmp = splitfirst(html, '<!--ShowThumbnailsStart-->');
            html = tmp[0];
            tmp = splitfirst(tmp[1], '<!--ShowThumbnailsEnd-->');
            let disableShowThumb = await getConfig('disableShowThumb');
            if (disableShowThumb=='') {
                html += tmp[0].replace('<!--constStr@OriginalPic-->', '原图');
            }
            html += tmp[1];
        }
        
        let imgextstr = JSON.stringify(exts['img']);
        imgextstr = imgextstr.substr(1, imgextstr.length-2);
        html = html.replace('<!--ImgExts-->', imgextstr);

  html = html.replace(/<!--Sitename-->/g, sitename);

  tmp = splitfirst(html, '<!--HeadomfStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--HeadomfEnd-->');
        if (('list' in files) && ('head.omf' in files['list'])) {
            //let headomfcontent = files['list']['head.omf'];
            let headomfcontent = await get_content(spurlencode(path_format(path + '/head.omf'), '/'));
            //console.log(headomfcontent);
            let headomfbody = headomfcontent['content']['body'];
            let headomf = tmp[0].replace('<!--HeadomfContent-->', headomfbody);
            html += headomf;
        }
        html += tmp[1];
        
        tmp = splitfirst(html, '<!--HeadmdStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--HeadmdEnd-->');
        if (('list' in files) && ('head.md' in files['list'])) {
            let headmdcontent = await get_content(spurlencode(path_format(path + '/head.md'), '/'));
            //console.log(headmdcontent);
            let headmdbody = headmdcontent['content']['body'];
            let headmd = tmp[0].replace('<!--HeadmdContent-->', headmdbody);
            //let headmd = tmp[0].replace('<!--HeadmdContent-->', await get_content(spurlencode(path_format(path + '/head.md'), '/'))['content']['body']);
            html += headmd + tmp[1];
            html = html.replace(/<!--HeadmdStart-->/g, '');
            html = html.replace(/<!--HeadmdEnd-->/g, '');
        } else {
            html += tmp[1];
            while (html.indexOf('<!--HeadmdStart-->')!==-1) {
                tmp = splitfirst(html, '<!--HeadmdStart-->');
                html = tmp[0];
                tmp = splitfirst(tmp[1], '<!--HeadmdEnd-->');
                html += tmp[1];
            }
        }

        while (html.indexOf('<!--ListStart-->')!==-1) {
                tmp = splitfirst(html, '<!--ListStart-->');
                html = tmp[0];
                tmp = splitfirst(tmp[1], '<!--ListEnd-->');
                if (JSON.stringify(files)!='{}') html += tmp[0];
                html += tmp[1];
            }
        tmp = splitfirst(html, '<!--ReadmemdStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--ReadmemdEnd-->');
        if (('list' in files) && ('readme.md' in files['list'])) {
            let readmemdcontent = await get_content(spurlencode(path_format(path + '/readme.md'), '/'));
            //console.log(headomfcontent);
            let readmebody = readmemdcontent['content']['body'];
            let Readmemd = tmp[0].replace('<!--ReadmemdContent-->', readmebody);
            //let Readmemd = tmp[0].replace('<!--ReadmemdContent-->', await get_content(spurlencode(path_format(path + '/head.md'), '/'))['content']['body']);
            html += Readmemd + tmp[1];
            html = html.replace(/<!--ReadmemdStart-->/g, '');
            html = html.replace(/<!--ReadmemdEnd-->/g, '');
        } else {
            html += tmp[1];
            while (html.indexOf('<!--ReadmemdStart-->')!==-1) {
                tmp = splitfirst(html, '<!--ReadmemdStart-->');
                html = tmp[0];
                tmp = splitfirst(tmp[1], '<!--ReadmemdEnd-->');
                html += tmp[1];
            }
        }
        tmp = splitfirst(html, '<!--FootomfStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--FootomfEnd-->');
        if (('list' in files) && ('foot.omf' in files['list'])) {
            let footomfcontent = await get_content(spurlencode(path_format(path + '/foot.omf'), '/'));
            //console.log(headomfcontent);
            let footomfbody = footomfcontent['content']['body'];
            let Footomf = tmp[0].replace('<!--FootomfContent-->', footomfbody);
            //let Footomf = tmp[0].replace('<!--FootomfContent-->', await get_content(spurlencode(path_format(path + '/head.omf'), '/'))['content']['body']);
            html += Footomf;
        }
        html += tmp[1];

        tmp = splitfirst(html, '<!--MdRequireStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--MdRequireEnd-->');
        if ((('list' in files) && ('head.md' in files['list']))||(('list' in files) && ('readme.md' in files['list']))) {
            html += tmp[0];
        }
        html += tmp[1];

        if (await getConfig('passfile')!='') {
            tmp = splitfirst(html, '<!--EncryptBtnStart-->');
            html = tmp[0];
            tmp = splitfirst(tmp[1], '<!--EncryptBtnEnd-->');
            html += tmp[0].replace('<!--constStr@Encrypt-->', '加油') + tmp[1];
            tmp = splitfirst(html, '<!--EncryptAlertStart-->');
            html = tmp[0];
            tmp = splitfirst(tmp[1], '<!--EncryptAlertEnd-->');
            html += tmp[1];
        } else {
            tmp = splitfirst(html, '<!--EncryptAlertStart-->');
            html = tmp[0];
            tmp = splitfirst(tmp[1], '<!--EncryptAlertEnd-->');
            html += tmp[0].replace('<!--constStr@SetpassfileBfEncrypt-->', '先设置passfile才能加密') + tmp[1];
            tmp = splitfirst(html, '<!--EncryptBtnStart-->');
            html = tmp[0];
            tmp = splitfirst(tmp[1], '<!--EncryptBtnEnd-->');
            html += tmp[1];
        }

        tmp = splitfirst(html, '<!--MoveRootStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--MoveRootEnd-->');
        if (path != '/') {
            html += tmp[0].replace('<!--constStr@ParentDir-->', '上级目录');
        }
        html += tmp[1];

        tmp = splitfirst(html, '<!--MoveDirsStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--MoveDirsEnd-->');
        let MoveDirs = tmp[0];
        if (('type' in files) && files['type']=='folder') {
            for (let key in files['list']) {
                let file = files['list'][key];

                if (('type' in file) && file['type']=='folder') {
                    //str_replace('&','&amp;', $file['name'])
                    let MoveDirsStr = MoveDirs.replace(/<!--MoveDirsValue-->/g, file['name']);
                    html += MoveDirsStr;
                }
            }
        }
        html += tmp[1];

        tmp = splitfirst(html, '<!--WriteTimezoneStart-->');
        html = tmp[0];
        tmp = splitfirst(tmp[1], '<!--WriteTimezoneEnd-->');
        //if (!('timezone' in COOKIE)) html += tmp[0].replace('<!--timezone-->', SERVER['timezone']);
        html += tmp[1];
        html = html.replace(/<!--timezone-->/g, SERVER['timezone']);

        
        if (html.indexOf('{{.RawData}}')!==-1) {
            let str = '[';
            let i = 0;
            for (let key in files['list']) {
                let file = files['list'][key];
                if (SERVER['admin'] || !isHideFile(file['name'])) {
                    let file_tmp = new Object();
                file_tmp['name'] = file['name'];
                file_tmp['size'] = size_format(file['size']);
                file_tmp['date'] = time_format(file['lastModifiedDateTime']);
                file_tmp['@time'] = file['date'];
                file_tmp['@type'] = (file['type']=='folder')?'folder':'file';
                str += JSON.stringify(file_tmp) + ',';
                }
            }
            if (str == '[') {
                str = '';
            } else str = str.substr(0, str.length-1) + ']';
            html = html.replace('{{.RawData}}', btoa(str));
        }

        //清除换行
        while (html.indexOf('\n\n')!==-1) html = html.replace(/\n\n/g, '\n');

    tmp = splitfirst(html, '</title>');
    html = tmp[0] + '</title>' + authinfo + tmp[1];

    //html += JSON.stringify(files, null, 2);

  let out_body = html;
  let out_stat = 200;
  let out_headers = new Headers();
  if ('Set-Cookie' in SERVER) out_headers.set('Set-Cookie', SERVER['Set-Cookie']);
  out_headers.set('Content-Type', 'text/html');
  return output(out_body, out_stat, out_headers);
}
