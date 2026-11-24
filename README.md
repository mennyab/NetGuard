# 🛡️ NetGuard

**NetGuard** connects to an enterprise network, automatically discovers its switches, routers,
and end devices, and builds a graphical topology map — reaching remote segments through device
pivoting (nested Telnet/SSH) when they aren't directly routable. It scans each device for
vulnerabilities — weak passwords, open ports, insecure services, and risky configurations — and
produces a report with a security score per component. For every finding it proposes an exact
remediation command that is **applied only after explicit user approval**, with a configuration
backup and rollback option.

> Built with Python + Streamlit · netmiko · scapy · nmap · pysnmp · networkx/pyvis

---

מערכת שמגלה את ההתקנים ברשת הארגונית, ממפה את הטופולוגיה, מאתרת חולשות ומציעה תיקונים. תיקון מתבצע **רק באישור המשתמש**.

## דרישות מוקדמות (Windows)
- Python 3.12 (מומלץ. חלק מספריות הרשת עדיין לא תומכות ב-3.14)
- [Nmap](https://nmap.org/download.html) ו-Npcap
- הרצה כמנהל (Run as Administrator), נדרש לסריקת ARP ו-nmap

## התקנה
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## הרצה
```powershell
streamlit run app.py
```

## מבנה הפרויקט
```
app.py                  נקודת כניסה (Streamlit)
config/                 הגדרות, מדיניות סיסמאות, סיסמאות ברירת מחדל
core/
  models.py             מודלי נתונים
  session_manager.py    ניהול חיבורים שלא מנתק סשנים קיימים
  discovery.py          גילוי התקנים
  topology.py           בניית הטופולוגיה
  assessment/           בדיקות חולשות (סיסמאות, פורטים, קונפיגורציה)
  mitigation.py         תוכנית תיקון וביצוע לאחר אישור
storage/                SQLite, גיבויי קונפיגורציה, יומן ביקורת
reports/templates/      תבניות דוחות
pages/                  9 מסכי המערכת
ui/                     עזרי תצוגה (RTL)
```

## המסכים (זרימת העבודה)
1. **הגדרות וגישה** — תת-רשתות, מתגים/נתבים עם סיסמאות (מוצפנות), בדיקת חיבור.
2. **סריקה** — גילוי התקנים (ARP → יצרן → nmap → SNMP → סיווג) עם יומן חי.
3. **טופולוגיה** — זחילה ממתג התחלתי לפי CDP/LLDP/OSPF, מפה אינטראקטיבית.
4. **רשימת התקנים** — טבלה, סינון, חיפוש, ייצוא CSV.
5. **פרטי התקן** — פורטים, ממשקים, חולשות וקונפיגורציה.
6. **דוח חולשות** — סיכום, גרפים וציון רשת.
7. **תוכנית תיקון** — המלצות ופקודות, אישור בלעדי של המשתמש.
8. **ביצוע ותוצאות** — גיבוי, ביצוע, אימות ו-Rollback.
9. **דוחות והיסטוריה** — דוח מנהלים/טכני (PDF/HTML), השוואה, יומן ביקורת.

> **הערה על דוחות PDF:** הדוחות ב-HTML מוצגים בעברית מלאה ומסודרת בדפדפן. ל-PDF
> מוטמע גופן עברי מהמערכת. אם העברית ב-PDF אינה מסודרת, עדיף לפתוח את דוח ה-HTML
> בדפדפן ולהדפיס ל-PDF משם (Ctrl+P → Save as PDF).

## עקרונות בטיחות
- המערכת לא מנתקת אף פעם חיבורים קיימים להתקן ולא מריצה `clear line`, `reload` וכדומה.
- יש לכל היותר 5 ניסיונות התחברות להתקן, עם השהיה ביניהם ועצירה כשמזוהה נעילה.
- בשלב הגילוי רצות רק פקודות קריאה (`show`).
- שינוי בקונפיגורציה מתבצע רק אחרי אישור מפורש של המשתמש, ואחרי גיבוי.
- סיסמאות לא נשמרות בטקסט גלוי.
