
import base64, hashlib, html, json, sqlite3, re, webbrowser
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP="SECURITY AUDITOR V5"
ROOT=Path(__file__).resolve().parent
DB=ROOT/"auditor.db"; REPORTS=ROOT/"reports"; REPORTS.mkdir(exist_ok=True)
BG="#090b10"; PANEL="#10141c"; PANEL2="#151a24"; BORDER="#252d3a"
TEXT="#eef2f8"; MUTED="#8f9bad"; ACCENT="#7c5cff"; RED="#ff5573"; ORANGE="#ff9f43"; GREEN="#46d89b"
SUSPICIOUS={"correctanswer","correct_answer","correctoption","correct_option","gabarito","solution","solucao","correctvalue","correct_value"}
SECRETISH={"authorization","cookie","set-cookie","access_token","refresh_token","password","passwd","client_secret","api_key","apikey","secret"}

def init_db():
    c=sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT,source TEXT,findings INTEGER,critical INTEGER,high INTEGER,medium INTEGER,low INTEGER)")
    c.execute("""CREATE TABLE IF NOT EXISTS findings(
    id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER,field TEXT,path TEXT,kind TEXT,severity TEXT,
    confidence TEXT,exposure TEXT,evidence_hash TEXT,value_length INTEGER,note TEXT,
    UNIQUE(scan_id,path,field,evidence_hash))""")
    c.commit(); c.close()

def b64(s):
    if not isinstance(s,str) or len(s)<4 or len(s)>4096 or len(s)%4==1 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}",s): return None
    try:
        t=base64.b64decode(s,validate=True).decode("utf-8")
        return t if t and all(c.isprintable() or c in "\r\n\t" for c in t) else None
    except Exception:return None

def walk(o,p="$"):
    if isinstance(o,dict):
        for k,v in o.items():
            q=f"{p}.{k}"; yield k,q,v; yield from walk(v,q)
    elif isinstance(o,list):
        for i,v in enumerate(o[:1000]):
            q=f"{p}[{i}]"; yield str(i),q,v; yield from walk(v,q)

def analyze(data):
    out=[]
    for field,path,val in walk(data):
        fl=field.lower(); raw=str(val)
        if fl in SECRETISH:
            out.append(dict(field=field,path=path,kind="sensitive-field",severity="CRITICAL",confidence="HIGH",exposure="field-present",evidence_hash=hashlib.sha256(raw.encode()).hexdigest()[:16],value_length=len(raw),note="Sensitive field detected; value intentionally withheld."))
            continue
        if not (fl in SUSPICIOUS or ("correct" in fl and isinstance(val,(str,int,float,bool)))): continue
        dec=b64(raw[1:]) if len(raw)>1 else None
        if dec is not None:
            kind="weak-obfuscation/base64"; sev="HIGH"; exp="recoverable"; conf="HIGH"
            note="Recoverable client-side representation detected; decoded value intentionally withheld."
        else:
            kind="plaintext-or-unknown"; sev="MEDIUM"; exp="present"; conf="MEDIUM"
            if raw.strip() and (len(raw)<=3 or " " in raw): sev="HIGH"; conf="HIGH"
            note="Suspicious answer-related field detected; value intentionally withheld."
        out.append(dict(field=field,path=path,kind=kind,severity=sev,confidence=conf,exposure=exp,evidence_hash=hashlib.sha256(raw.encode()).hexdigest()[:16],value_length=len(raw),note=note))
    return out

def save_scan(source,fs):
    c={x:0 for x in ("CRITICAL","HIGH","MEDIUM","LOW")}
    for f in fs:c[f["severity"]]+=1
    db=sqlite3.connect(DB)
    cur=db.execute("INSERT INTO scans VALUES(NULL,?,?,?,?,?,?,?)",(datetime.now().astimezone().isoformat(timespec="seconds"),source,len(fs),c["CRITICAL"],c["HIGH"],c["MEDIUM"],c["LOW"]))
    sid=cur.lastrowid
    for f in fs:
        db.execute("""INSERT OR IGNORE INTO findings(scan_id,field,path,kind,severity,confidence,exposure,evidence_hash,value_length,note)
        VALUES(?,?,?,?,?,?,?,?,?,?)""",(sid,f["field"],f["path"],f["kind"],f["severity"],f["confidence"],f["exposure"],f["evidence_hash"],f["value_length"],f["note"]))
    db.commit();db.close();return sid,c

def totals():
    c=sqlite3.connect(DB);r=c.execute("SELECT COUNT(*),COALESCE(SUM(findings),0),COALESCE(SUM(critical),0),COALESCE(SUM(high),0),COALESCE(SUM(medium),0),COALESCE(SUM(low),0) FROM scans").fetchone();c.close();return r

def scans():
    c=sqlite3.connect(DB);r=c.execute("SELECT id,created_at,source,findings,critical,high,medium,low FROM scans ORDER BY id DESC LIMIT 200").fetchall();c.close();return r

def export(scan_id):
    c=sqlite3.connect(DB); s=c.execute("SELECT * FROM scans WHERE id=?",(scan_id,)).fetchone()
    rows=c.execute("SELECT field,path,kind,severity,confidence,exposure,evidence_hash,value_length,note FROM findings WHERE scan_id=? ORDER BY id",(scan_id,)).fetchall();c.close()
    cols=["field","path","kind","severity","confidence","exposure","evidence_hash","value_length","note"];data=[dict(zip(cols,r)) for r in rows]
    stamp=datetime.now().strftime("%Y%m%d_%H%M%S");summary={"findings":len(rows),"critical":s[4],"high":s[5],"medium":s[6],"low":s[7]}
    jp=REPORTS/f"scan_{stamp}.json";jp.write_text(json.dumps({"application":APP,"generated_at":datetime.now().astimezone().isoformat(timespec="seconds"),"scan_id":scan_id,"summary":summary,"findings":data},indent=2,ensure_ascii=False),encoding="utf-8")
    md=REPORTS/f"scan_{stamp}.md";md.write_text("# "+APP+f" — Scan #{scan_id}\n\n## Summary\n"+json.dumps(summary,indent=2)+"\n\n> Sensitive and decoded values intentionally excluded.\n",encoding="utf-8")
    cards="".join(f"<article class='finding {f['severity'].lower()}'><b>{html.escape(f['severity'])}</b><h3>{html.escape(f['field'])}</h3><p><code>{html.escape(f['path'])}</code></p><p>{html.escape(f['note'])}</p><small>{html.escape(f['kind'])} · {html.escape(f['evidence_hash'])}</small></article>" for f in data)
    hp=REPORTS/f"scan_{stamp}.html";hp.write_text(f"""<!doctype html><meta charset=utf-8><title>{APP}</title><style>body{{background:#090b10;color:#eef2f8;font:15px Segoe UI;padding:40px}}main{{max-width:1100px;margin:auto}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}}.card,.finding{{background:#131821;border:1px solid #272e3a;border-radius:18px;padding:20px;margin:12px 0}}.num{{font-size:30px;font-weight:700}}.muted{{color:#8f9bad}}.critical{{border-left:5px solid #ff5573}}.high{{border-left:5px solid #ff9f43}}.medium{{border-left:5px solid #ffd166}}.low{{border-left:5px solid #46d89b}}code{{color:#b9c8ff}}</style><main><h1>🛡️ {APP}</h1><p class=muted>Offline exposure report · Scan #{scan_id}</p><div class=grid><div class=card>Findings<div class=num>{len(rows)}</div></div><div class=card>Critical<div class=num>{s[4]}</div></div><div class=card>High<div class=num>{s[5]}</div></div><div class=card>Recoverable<div class=num>{sum(f['exposure']=='recoverable' for f in data)}</div></div></div><h2>Findings</h2>{cards or "<div class=card>No suspicious exposure found.</div>"}</main>""",encoding="utf-8")
    return [hp,jp,md]

class App(tk.Tk):
    def __init__(self):
        super().__init__();init_db();self.title(APP);self.geometry("1400x860");self.minsize(1120,720);self.configure(bg=BG)
        self.option_add("*Font", ("Segoe UI", 10))
        st=ttk.Style(self);st.theme_use("clam");st.configure("Treeview",background=PANEL,foreground=TEXT,fieldbackground=PANEL,rowheight=34,font=("Segoe UI",10),borderwidth=0);st.configure("Treeview.Heading",background=PANEL2,foreground=MUTED,font=("Segoe UI Semibold",9))
        self.side=tk.Frame(self,bg="#0c0f15",width=235);self.side.pack(side="left",fill="y");self.side.pack_propagate(False)
        brand = tk.Frame(self.side,bg="#0c0f15")
        brand.pack(fill="x",padx=22,pady=(25,28))
        tk.Label(brand,text="🛡",bg="#0c0f15",fg=ACCENT,font=("Segoe UI Emoji",30)).pack(anchor="w")
        tk.Label(brand,text="SECURITY",bg="#0c0f15",fg=TEXT,font=("Segoe UI Semibold",19)).pack(anchor="w")
        tk.Label(brand,text="AUDITOR",bg="#0c0f15",fg=ACCENT,font=("Segoe UI Semibold",19)).pack(anchor="w")
        tk.Label(brand,text="V5.1  •  VISUAL EDITION",bg="#0c0f15",fg=MUTED,font=("Segoe UI Semibold",8)).pack(anchor="w",pady=(4,0))
        self.status_dot = tk.Label(self.side,text="●  SYSTEM READY",bg="#0c0f15",fg=GREEN,font=("Segoe UI Semibold",8))
        self.status_dot.pack(anchor="w",padx=22,pady=(0,18))
        for text,cmd in [("⌂  Dashboard",self.dashboard),("⌕  New Scan",self.scan_page),("▦  Findings",self.findings),("◷  History",self.history),("▤  Reports",self.reports)]:
            tk.Button(self.side,text=text,command=cmd,anchor="w",bg="#0c0f15",fg=MUTED,activebackground="#171222",activeforeground=TEXT,bd=0,font=("Segoe UI Semibold",11),padx=22,pady=12,cursor="hand2").pack(fill="x")
        tk.Frame(self.side,bg="#0c0f15").pack(expand=True);tk.Label(self.side,text="●  LOCAL / NO NETWORK",bg="#0c0f15",fg=GREEN,font=("Segoe UI Semibold",8)).pack(pady=18)
        self.main=tk.Frame(self,bg=BG);self.main.pack(side="right",fill="both",expand=True)
        self.fade_alpha = 0
        self.dashboard()

    def clear(self):
        for w in self.main.winfo_children():w.destroy()
    def head(self,t,s):
        f=tk.Frame(self.main,bg=BG);f.pack(fill="x",padx=32,pady=(28,20))
        tk.Label(f,text="V5.1",bg="#171225",fg=ACCENT,font=("Segoe UI Semibold",8),padx=9,pady=4).pack(anchor="e")
        tk.Label(f,text=t,bg=BG,fg=TEXT,font=("Segoe UI Semibold",25)).pack(anchor="w");tk.Label(f,text=s,bg=BG,fg=MUTED,font=("Segoe UI",10)).pack(anchor="w",pady=(3,0))
        tk.Frame(f,bg=ACCENT,height=2,width=72).pack(anchor="w",pady=(12,0))
    def card(self,p,l,v,a):
        f=tk.Frame(p,bg=PANEL,highlightbackground=BORDER,highlightthickness=1);f.pack(side="left",fill="both",expand=True,padx=6);tk.Frame(f,bg=a,width=4).pack(side="left",fill="y");b=tk.Frame(f,bg=PANEL);b.pack(fill="both",expand=True,padx=18,pady=16);tk.Label(b,text=l.upper(),bg=PANEL,fg=MUTED,font=("Segoe UI Semibold",8)).pack(anchor="w");tk.Label(b,text=v,bg=PANEL,fg=TEXT,font=("Segoe UI Semibold",25)).pack(anchor="w",pady=(5,0))
    def tree(self,p,cols,widths):
        w=tk.Frame(p,bg=PANEL);w.pack(fill="both",expand=True,padx=16,pady=(0,16));tr=ttk.Treeview(w,columns=cols,show="headings")
        for c,x in zip(cols,widths):tr.heading(c,text=c);tr.column(c,width=x,anchor="w")
        sb=ttk.Scrollbar(w,orient="vertical",command=tr.yview);tr.configure(yscrollcommand=sb.set);tr.pack(side="left",fill="both",expand=True);sb.pack(side="right",fill="y");return tr
    def pulse_ready(self, step=0):
        if not self.winfo_exists(): return
        shades = [GREEN, "#6fe5b0", GREEN, "#5bd6a4"]
        self.status_dot.configure(fg=shades[step % len(shades)])
        self.after(900, self.pulse_ready, step+1)

    def animate_number(self, label, target, duration=650):
        try: target=int(target)
        except: label.configure(text=str(target)); return
        steps=max(1, duration//30); current=0
        def tick(i=0):
            value=round(target*i/steps)
            label.configure(text=str(value))
            if i<steps: self.after(30,tick,i+1)
        tick()

    def chart_bar(self, parent, name, value, maximum, accent):
        row=tk.Frame(parent,bg=PANEL); row.pack(fill="x",padx=20,pady=7)
        top=tk.Frame(row,bg=PANEL); top.pack(fill="x")
        tk.Label(top,text=name,bg=PANEL,fg=TEXT,font=("Segoe UI Semibold",9)).pack(side="left")
        tk.Label(top,text=str(value),bg=PANEL,fg=MUTED,font=("Segoe UI Semibold",9)).pack(side="right")
        track=tk.Frame(row,bg="#202633",height=9); track.pack(fill="x",pady=(5,0))
        if maximum:
            width=max(2,int(300*value/maximum))
        else: width=2
        fill=tk.Frame(track,bg=accent,height=9,width=width); fill.pack(side="left")
        return fill

    def dashboard(self):
        self.clear(); self.head("Dashboard","Centro de controle • análise local • visão operacional")
        t=totals()
        cards=tk.Frame(self.main,bg=BG);cards.pack(fill="x",padx=26)
        def make_card(title, value, accent, icon):
            f=tk.Frame(cards,bg=PANEL,highlightbackground=BORDER,highlightthickness=1,height=118)
            f.pack(side="left",fill="both",expand=True,padx=6);f.pack_propagate(False)
            tk.Frame(f,bg=accent,width=4).pack(side="left",fill="y")
            b=tk.Frame(f,bg=PANEL);b.pack(fill="both",expand=True,padx=18,pady=14)
            tk.Label(b,text=icon,bg=PANEL,fg=accent,font=("Segoe UI Emoji",20)).pack(anchor="w")
            tk.Label(b,text=title.upper(),bg=PANEL,fg=MUTED,font=("Segoe UI Semibold",8)).pack(anchor="w")
            n=tk.Label(b,text="0",bg=PANEL,fg=TEXT,font=("Segoe UI Semibold",24));n.pack(anchor="w")
            self.animate_number(n,value);return f
        make_card("Scans",t[0],ACCENT,"◈");make_card("Findings",t[1],TEXT,"⌕")
        make_card("Critical",t[2],RED,"⚠");make_card("High",t[3],ORANGE,"◆")

        body=tk.Frame(self.main,bg=BG);body.pack(fill="both",expand=True,padx=32,pady=22)
        left=tk.Frame(body,bg=PANEL,highlightbackground=BORDER,highlightthickness=1)
        left.pack(side="left",fill="both",expand=True,padx=(0,9))
        tk.Label(left,text="Threat distribution",bg=PANEL,fg=TEXT,font=("Segoe UI Semibold",15)).pack(anchor="w",padx=20,pady=(20,4))
        tk.Label(left,text="Distribuição visual dos achados acumulados",bg=PANEL,fg=MUTED,font=("Segoe UI",9)).pack(anchor="w",padx=20,pady=(0,14))
        mx=max(1,t[2]+t[3]+t[4]+t[5])
        self.chart_bar(left,"CRITICAL",t[2],mx,RED);self.chart_bar(left,"HIGH",t[3],mx,ORANGE)
        self.chart_bar(left,"MEDIUM",t[4],mx,YELLOW);self.chart_bar(left,"LOW",t[5],mx,GREEN)

        tk.Label(left,text="Recent activity",bg=PANEL,fg=TEXT,font=("Segoe UI Semibold",13)).pack(anchor="w",padx=20,pady=(20,10))
        tr=self.tree(left,("ID","DATA","FINDINGS","CRIT","HIGH"),(65,210,90,70,70))
        for x in scans()[:5]: tr.insert("", "end",values=(x[0],x[1].replace("T"," "),x[3],x[4],x[5]))

        right=tk.Frame(body,bg=PANEL,highlightbackground=BORDER,highlightthickness=1,width=300)
        right.pack(side="right",fill="y",padx=(9,0));right.pack_propagate(False)
        tk.Label(right,text="Quick actions",bg=PANEL,fg=TEXT,font=("Segoe UI Semibold",15)).pack(anchor="w",padx=20,pady=(20,5))
        tk.Label(right,text="Acesso rápido às principais funções",bg=PANEL,fg=MUTED,font=("Segoe UI",9)).pack(anchor="w",padx=20,pady=(0,14))
        for txt,cmd in [("＋  Nova auditoria",self.scan_page),("▦  Findings",self.findings),("◷  Histórico",self.history),("▤  Relatórios",self.reports)]:
            b=tk.Button(right,text=txt,command=cmd,bg=PANEL2,fg=TEXT,activebackground="#211b36",activeforeground="white",bd=0,anchor="w",padx=15,pady=12,font=("Segoe UI Semibold",10),cursor="hand2")
            b.pack(fill="x",padx=20,pady=5)
        sep=tk.Frame(right,bg=BORDER,height=1);sep.pack(fill="x",padx=20,pady=20)
        tk.Label(right,text="PRIVACY MODE",bg=PANEL,fg=GREEN,font=("Segoe UI Semibold",9)).pack(anchor="w",padx=20)
        tk.Label(right,text="Local only\nNo network\nSensitive values withheld",bg=PANEL,fg=MUTED,justify="left",font=("Segoe UI",9),pady=8).pack(anchor="w",padx=20)
        self.after(400,self.pulse_ready)

    def scan_page(self):
        self.clear();self.head("Nova auditoria","Cole um JSON capturado ou importe um arquivo local")
        self.text=tk.Text(self.main,bg="#0d1118",fg=TEXT,insertbackground=TEXT,relief="flat",font=("Cascadia Mono",10),padx=16,pady=16);self.text.pack(fill="both",expand=True,padx=32)
        self.scan_hint=tk.Label(self.main,text="READY • JSON local • máximo 5 MB",bg=BG,fg=MUTED,font=("Segoe UI",9))
        self.scan_hint.pack(anchor="w",padx=34,pady=(7,0))
        bar=tk.Frame(self.main,bg=BG);bar.pack(fill="x",padx=32,pady=16)
        tk.Button(bar,text="📂 Importar JSON",command=self.import_json,bg=PANEL2,fg=TEXT,bd=0,padx=18,pady=11,font=("Segoe UI Semibold",10)).pack(side="left")
        tk.Button(bar,text="🧹 Limpar",command=lambda:self.text.delete("1.0","end"),bg=PANEL2,fg=TEXT,bd=0,padx=18,pady=11,font=("Segoe UI Semibold",10)).pack(side="left",padx=8)
        tk.Button(bar,text="▶  EXECUTAR SCAN",command=self.run,bg=ACCENT,fg="white",bd=0,padx=22,pady=11,font=("Segoe UI Semibold",10)).pack(side="right")
    def import_json(self):
        p=filedialog.askopenfilename(filetypes=[("JSON","*.json"),("Todos","*.*")])
        if p:
            try:
                raw=Path(p).read_text(encoding="utf-8");json.loads(raw)
                if len(raw)>5_000_000:raise ValueError("Arquivo maior que 5 MB.")
                self.text.delete("1.0","end");self.text.insert("1.0",raw)
            except Exception as e:messagebox.showerror("JSON inválido",str(e))
    def run(self):
        try:
            raw=self.text.get("1.0","end").strip()
            if not raw:raise ValueError("Cole ou importe um JSON.")
            if len(raw)>5_000_000:raise ValueError("Entrada maior que 5 MB.")
            self.scan_hint.configure(text="● ANALYZING…",fg=ACCENT)
            self.update_idletasks()
            fs=analyze(json.loads(raw));sid,c=save_scan("manual JSON capture",fs);export(sid)
            self.scan_hint.configure(text=f"● SCAN #{sid} COMPLETE • {len(fs)} findings",fg=GREEN)
            self.findings(sid)
            messagebox.showinfo("Scan concluído",f"Scan #{sid}\n\nFindings: {len(fs)}\nCritical: {c['CRITICAL']}\nHigh: {c['HIGH']}\nMedium: {c['MEDIUM']}")
        except Exception as e:messagebox.showerror("Falha na auditoria",str(e))
    def findings(self,sid=None):
        self.clear();self.head("Findings","Achados registrados no banco local");top=tk.Frame(self.main,bg=BG);top.pack(fill="x",padx=32,pady=(0,12));tk.Label(top,text="Filtro",bg=BG,fg=MUTED).pack(side="left")
        v=tk.StringVar(value="TODOS");box=ttk.Combobox(top,textvariable=v,values=["TODOS","CRITICAL","HIGH","MEDIUM","LOW"],state="readonly",width=12);box.pack(side="left",padx=8)
        tr=self.tree(self.main,("ID","SCAN","SEVERITY","FIELD","PATH","DETECTION","EXPOSURE"),(60,60,100,150,280,180,110))
        c=sqlite3.connect(DB);q="SELECT id,scan_id,severity,field,path,kind,exposure FROM findings";args=()
        if sid:q+=" WHERE scan_id=?";args=(sid,)
        q+=" ORDER BY id DESC";rows=c.execute(q,args).fetchall();c.close()
        def fill(*_):
            tr.delete(*tr.get_children());f=v.get()
            for x in rows:
                if f=="TODOS" or x[2]==f:tr.insert("", "end",values=x)
        box.bind("<<ComboboxSelected>>",fill);fill()
    def history(self):
        self.clear();self.head("Scan History","Todas as auditorias salvas localmente");tr=self.tree(self.main,("ID","DATA","SOURCE","FINDINGS","CRITICAL","HIGH","MEDIUM","LOW"),(60,180,180,90,80,70,80,60))
        for x in scans():tr.insert("", "end",values=x)
    def reports(self):
        self.clear();self.head("Reports","Relatórios HTML, JSON e Markdown gerados automaticamente");tr=self.tree(self.main,("ARQUIVO","TIPO","TAMANHO"),(520,120,120))
        files=sorted(REPORTS.glob("*"),key=lambda p:p.stat().st_mtime,reverse=True)
        for p in files:tr.insert("", "end",values=(p.name,p.suffix.upper().replace(".",""),f"{p.stat().st_size/1024:.1f} KB"))
        def openit():
            s=tr.selection()
            if s:webbrowser.open((REPORTS/tr.item(s[0],"values")[0]).resolve().as_uri())
        tk.Button(self.main,text="🌐 Abrir selecionado",command=openit,bg=ACCENT,fg="white",bd=0,padx=20,pady=10,font=("Segoe UI Semibold",10)).pack(anchor="e",padx=32,pady=12)

if __name__=="__main__":
    App().mainloop()
