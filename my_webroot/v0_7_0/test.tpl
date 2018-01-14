{{> header.tpl}}
<b>hello {{val}}!</b>
<br/>
<h3>{{ zl }}</h3>
<h3>{{{ zl }}}</h3>
<h3>{{& zl }}</h3>

<p><b>score: {{ score }}</b></p>
<p><b>score: {{{ score }}}</b></p>
<p><b>score: {{& score }}</b></p>

<p><b>money: {{ money }}$</b></p>

{{#dts}}
<div style="padding-bottom:5px">{{name}} : {{job}}</div>
{{/dts}}

<br/>
<table>
{{# schools}} {{! 循环将schools里的成员显示出来}}
	<tr><td>{{ . }}</td></tr>
{{/ schools}}
{{^ schools}}
	<tr><td>暂无schools信息</td></tr>
{{/ schools}}
</table>

<br/>
<span>使用&lt;%...%&gt;作为分隔符</span><br/>
{{=<% %>=}}
<%# userinfo %><p><span>user name: <% name %></span>
<span style="margin-left:25px;">from: <% from %></span></p><%/ userinfo %>

<p>恢复使用{{...}}作为分隔符</p>
<%={{ }}=%>
{{! 加载footer.tpl底部模板}}
{{> footer.tpl}}
