import os
import ipaddress
import configparser
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
import time
from fail2ban_service import Fail2banService, parse_global_status, parse_jail_status
from ssh_analysis_service import SshAnalysisService
from geo_service import GeoService

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

from datetime import datetime, timedelta
# SQLAlchemy and Login setup (initialized later in create_app)
db = SQLAlchemy()
login_manager = LoginManager()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change-me")
    # Database config (SQLite by default)
    db_path = os.getenv("DATABASE_URL") or "sqlite:///app.db"
    app.config["SQLALCHEMY_DATABASE_URI"] = db_path
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"

    @app.before_request
    def _enforce_login_everywhere():
        from flask import request as _rq
        # Allow static assets and login endpoints without auth
        path = (_rq.path or "/").lower()
        if path.startswith('/static') or path == '/favicon.ico':
            return None
        if _rq.endpoint in ("login", "login_post", "root_redirect"):
            return None
        # Already authenticated: allow
        if current_user.is_authenticated:
            return None
        # Otherwise, redirect to login
        return redirect(url_for('login', next=_rq.url))

    use_sudo_flag = os.getenv("F2B_SUDO", "false").lower() in ("1", "true", "yes")
    service = Fail2banService(
        cmd=os.getenv("F2B_CMD", "fail2ban-client"),
        use_sudo=use_sudo_flag,
    )
    defaults_path = os.getenv("F2B_DEFAULTS_FILE", "/etc/fail2ban/jail.d/defaults-debian.conf")
    ssh_use_sudo_flag = os.getenv("SSH_SUDO", "false").lower() in ("1", "true", "yes")
    ssh_service = SshAnalysisService(use_sudo=ssh_use_sudo_flag)
    geo_service = GeoService()

    # Ensure DB exists and default admin user
    with app.app_context():
        db.create_all()
        # ensure is_admin column exists for existing DBs
        try:
            db.session.execute(text('SELECT is_admin FROM user LIMIT 1'))
        except Exception:
            try:
                db.session.execute(text('ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 1 NOT NULL'))
                db.session.commit()
            except Exception:
                db.session.rollback()
        if not User.query.filter_by(username='admin').first():
            u = User(username='admin', is_admin=True)
            u.set_password(os.getenv('DEFAULT_ADMIN_PASSWORD','admin'))
            db.session.add(u)
            db.session.commit()

    @app.get("/login")
    def login():
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        username = request.form.get("username","" ).strip()
        password = request.form.get("password","" )
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash("Identifiants invalides.", "danger")
        return redirect(url_for("login"))

    @app.get("/logout")
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.get("/profile")
    @login_required
    def profile():
        return render_template("profile.html")

    def admin_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
                flash("Accès administrateur requis.", "danger")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapper

    @app.post("/profile")
    @login_required
    def profile_post():
        pwd = request.form.get("password","" )
        if not pwd:
            flash("Mot de passe requis.", "warning")
            return redirect(url_for("profile"))
        current_user.set_password(pwd)
        db.session.commit()
        flash("Mot de passe mis à jour.", "success")
        return redirect(url_for("profile"))

    @app.get("/")
    def root_redirect():
        return redirect(url_for("jails_index"))

    @app.get('/admin/users')
    @login_required
    def admin_users():
        users = User.query.order_by(User.id.asc()).all()
        return render_template('admin_users.html', users=users)

    @app.post('/admin/users/create')
    @login_required
    @admin_required
    def admin_user_create():
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        if not username or not password:
            flash('Utilisateur et mot de passe requis.', 'warning')
            return redirect(url_for('admin_users'))
        if User.query.filter_by(username=username).first():
            flash('Nom d\'utilisateur déjà utilisé.', 'warning')
            return redirect(url_for('admin_users'))
        u = User(username=username, is_admin=False)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash('Utilisateur créé.', 'success')
        return redirect(url_for('admin_users'))

    @app.post('/admin/users/<int:uid>/reset')
    @login_required
    @admin_required
    def admin_user_reset(uid):
        pwd = request.form.get('password') or ''
        if not pwd:
            flash('Mot de passe requis.', 'warning')
            return redirect(url_for('admin_users'))
        u = User.query.get_or_404(uid)
        u.set_password(pwd)
        db.session.commit()
        flash('Mot de passe réinitialisé.', 'success')
        return redirect(url_for('admin_users'))

    @app.post('/admin/users/<int:uid>/delete')
    @login_required
    @admin_required
    def admin_user_delete(uid):
        u = User.query.get_or_404(uid)
        if u.id == current_user.id:
            flash('Impossible de supprimer votre propre compte.', 'warning')
            return redirect(url_for('admin_users'))
        db.session.delete(u)
        db.session.commit()
        flash('Utilisateur supprimé.', 'success')
        return redirect(url_for('admin_users'))

    @app.get("/jails")
    @app.get("/jails/")
    @login_required
    def jails_index():
        ok, out, err, code = service.status()
        if not ok:
            flash(f"Erreur lors de l'obtention du statut: {err or out}", "danger")
            jails = []
        else:
            parsed = parse_global_status(out)
            jails = parsed.get("jails", [])
        metrics = {}
        for j in jails:
            okj, outj, errj, codej = service.status(j)
            if okj:
                metrics[j] = parse_jail_status(outj)
            else:
                metrics[j] = {"error": errj or outj}
        return render_template("index.html", jails=jails, metrics=metrics)

    @app.get("/jails/<jail>")
    @login_required
    def jail_detail(jail):
        ok, out, err, code = service.status(jail)
        if not ok:
            flash(f"Erreur statut pour {jail}: {err or out}", "danger")
            return render_template("jail.html", jail=jail, status={}, banned_times={})
        status = parse_jail_status(out)
        # Try to fetch timestamps for banned IPs
        ok_t, ip_ts, err_t, code_t = service.get_banned_with_times(jail)
        if not ok_t:
            ip_ts = {}
        return render_template("jail.html", jail=jail, status=status, banned_times=ip_ts)

    @app.post("/jails/<jail>/ban")
    @login_required
    def ban_ip(jail):
        ip = request.form.get("ip", "").strip()
        if not ip:
            flash("Veuillez fournir une adresse IP.", "warning")
            return redirect(url_for("jail_detail", jail=jail))
        if not is_valid_ip(ip):
            flash("Adresse IP invalide (IPv4/IPv6).", "warning")
            return redirect(url_for("jail_detail", jail=jail))
        ok, out, err, code = service.ban(jail, ip)
        out_s = (out or "").strip().lower()
        if ok:
            if out_s in ("1", "true", "ok", "yes"):
                flash(f"IP {ip} bannie dans {jail}.", "success")
            elif out_s in ("0", "false", "no"):
                flash(f"IP {ip} déjà bannie ou action non appliquée dans {jail}.", "warning")
            else:
                flash(f"Commande ban exécutée (code=0). Sortie: {out_s or '(vide)'}.", "info")
        else:
            flash(f"Échec du ban de {ip} dans {jail}: {err or out}", "danger")
        return redirect(url_for("jail_detail", jail=jail))

    @app.post("/jails/<jail>/unban")
    @login_required
    def unban_ip(jail):
        ip = request.form.get("ip", "").strip()
        if not ip:
            flash("Veuillez fournir une adresse IP.", "warning")
            return redirect(url_for("jail_detail", jail=jail))
        if not is_valid_ip(ip):
            flash("Adresse IP invalide (IPv4/IPv6).", "warning")
            return redirect(url_for("jail_detail", jail=jail))
        ok, out, err, code = service.unban(jail, ip)
        out_s = (out or "").strip().lower()
        if ok:
            if out_s in ("1", "true", "ok", "yes"):
                flash(f"IP {ip} débannie dans {jail}.", "success")
            elif out_s in ("0", "false", "no"):
                flash(f"IP {ip} n'était pas bannie dans {jail}.", "warning")
            else:
                flash(f"Commande unban exécutée (code=0). Sortie: {out_s or '(vide)'}.", "info")
        else:
            flash(f"Échec du déban de {ip} dans {jail}: {err or out}", "danger")
        return redirect(url_for("jail_detail", jail=jail))

    @app.post("/jails/<jail>/reload")
    @login_required
    def reload_jail(jail):
        ok, out, err, code = service.reload(jail)
        if ok:
            flash(f"Jail {jail} rechargé.", "success")
        else:
            flash(f"Échec du rechargement de {jail}: {err or out}", "danger")
        next_url = request.args.get("next")
        if next_url:
            return redirect(next_url)
        return redirect(url_for("jail_detail", jail=jail))

    @app.post("/reload")
    @login_required
    def reload_all():
        ok, out, err, code = service.reload(None)
        if ok:
            flash("Fail2ban rechargé.", "success")
        else:
            flash(f"Échec du rechargement global: {err or out}", "danger")
        return redirect(url_for("jails_index"))

    @app.post("/jails/<jail>/restart")
    @login_required
    def restart_jail(jail):
        ok, out, err, code = service.restart(jail)
        if ok:
            flash(f"Jail {jail} redémarré.", "success")
        else:
            flash(f"Échec du redémarrage de {jail}: {err or out}", "danger")
        next_url = request.args.get("next")
        if next_url:
            return redirect(next_url)
        return redirect(url_for("jail_detail", jail=jail))

    def _gather_f2b_metrics():
        ok, out, err, code = service.status()
        jails = []
        metrics = {}
        if ok:
            jails = parse_global_status(out).get("jails", [])
            for j in jails:
                okj, outj, errj, codej = service.status(j)
                if okj:
                    metrics[j] = parse_jail_status(outj)
                else:
                    metrics[j] = {"error": errj or outj}
        return {"jails": jails, "metrics": metrics}

    @app.get("/ssh/analysis")
    @login_required
    def ssh_analysis():
        since = request.args.get("since", "24 hours ago")
        ok, data, err = ssh_service.fetch_and_analyze(since=since, max_lines=10000)
        if not ok:
            flash(f"Erreur analyse SSH: {err}", "danger")
            data = {"totals": {}, "top_failed_ips": [], "top_accepted_ips": [], "top_failed_users": [], "top_accepted_users": [], "events": []}
        jails = []
        okj, outj, errj, codej = service.status()
        if okj:
            jails = parse_global_status(outj).get("jails", [])
        return render_template("ssh_analysis.html", data=data, since=since, jails=jails)

    @app.get("/dashboard")
    @login_required
    def dashboard():
        since_raw = request.args.get("since", "24h")
        since_norm, window_secs = _normalize_since(since_raw)
        ok, data, err = ssh_service.fetch_and_analyze(since=since_norm, max_lines=10000)
        if not ok:
            data = {"totals": {}, "top_failed_ips": [], "top_accepted_ips": [], "top_failed_users": [], "top_accepted_users": [], "events": []}
        geo_failed = geo_service.geolocate_many(data.get("top_failed_ips", []))
        # Build series from full set of events (not truncated for UI)
        ok_lines, lines, _err_lines = ssh_service.fetch_raw_lines(since=since_norm, max_lines=10000)
        evs_full = ssh_service.parse_events(lines) if ok_lines else data.get("events", [])
        series = _build_timeseries(evs_full, window_secs)
        # F2B metrics initial
        f2b = _gather_f2b_metrics()
        # Aggregate banned IPs across jails (count per IP = number of jails banning it)
        def _aggregate_banned_ips(metrics: dict) -> list[tuple[str,int]]:
            from collections import Counter
            c = Counter()
            for m in (metrics or {}).values():
                for ip in m.get("banned_list", []) or []:
                    if is_valid_ip(ip):
                        c[ip] += 1
            return list(c.items())
        banned_tuples = _aggregate_banned_ips(f2b.get("metrics", {}))
        geo_banned = geo_service.geolocate_many(banned_tuples)
        return render_template("dashboard.html", data=data, geo_failed=geo_failed, geo_banned=geo_banned, since=since_raw, series=series, f2b=f2b)

    def _normalize_since(s: str) -> tuple[str, int]:
        key = (s or "24h").strip().lower()
        mapping = {
            "1h": ("1 hour ago", 3600),
            "6h": ("6 hours ago", 6*3600),
            "24h": ("24 hours ago", 24*3600),
            "24": ("24 hours ago", 24*3600),
            "24hours": ("24 hours ago", 24*3600),
            "24 hours ago": ("24 hours ago", 24*3600),
            "7d": ("7 days ago", 7*86400),
            "7j": ("7 days ago", 7*86400),
            "7 days ago": ("7 days ago", 7*86400),
        }
        if key in mapping:
            return mapping[key]
        # fallback: pass-through to journalctl, default window 24h
        return (s, 24*3600)

    def _parse_ts(ts: str):
        try:
            if "T" in ts and len(ts) >= 19:
                return __import__("datetime").datetime.fromisoformat(ts[:19])
        except Exception:
            pass
        try:
            # syslog style: 'Aug  8 17:12:34'
            now = __import__("datetime").datetime.now()
            dt = __import__("datetime").datetime.strptime(f"{now.year} {ts}", "%Y %b %d %H:%M:%S")
            return dt
        except Exception:
            return None

    def _build_timeseries(events: list[dict], window_secs: int) -> dict:
        import datetime
        from collections import defaultdict
        end = datetime.datetime.now()
        start = end - datetime.timedelta(seconds=window_secs)

        # Choose aggregation step based on window size:
        # - <= 2h  -> 1 minute
        # - <= 6h  -> 10 minutes
        # - <= 48h -> 1 hour
        # - > 48h  -> 1 day
        if window_secs <= 2 * 3600:
            step = datetime.timedelta(minutes=1)
            fmt = "%H:%M"
        elif window_secs <= 6 * 3600:
            step = datetime.timedelta(minutes=10)
            fmt = "%H:%M"
        elif window_secs <= 48 * 3600:
            step = datetime.timedelta(hours=1)
            fmt = "%m-%d %Hh"
        else:
            step = datetime.timedelta(days=1)
            fmt = "%m-%d"

        labels = []
        stamp = start.replace(second=0, microsecond=0)
        # align stamp to step boundary for hour/day aggregations
        if step >= datetime.timedelta(hours=1):
            if step == datetime.timedelta(hours=1):
                stamp = stamp.replace(minute=0)
            if step >= datetime.timedelta(days=1):
                stamp = stamp.replace(hour=0, minute=0)

        values_failed = []
        values_accepted = []
        buckets = []
        failed_bucket_ips = []  # list[dict[ip,int]]
        accepted_bucket_ips = []
        while stamp <= end:
            labels.append(stamp.strftime(fmt))
            values_failed.append(0)
            values_accepted.append(0)
            buckets.append(stamp)
            failed_bucket_ips.append(defaultdict(int))
            accepted_bucket_ips.append(defaultdict(int))
            stamp += step
        # fill
        for ev in events:
            typ = ev.get("type")
            if typ not in ("failed", "accepted"):
                continue
            ts = ev.get("ts")
            dt = _parse_ts(ts) if isinstance(ts, str) else None
            if not dt or dt < start or dt > end:
                continue
            # find bucket index
            idx = int((dt - buckets[0]).total_seconds() // step.total_seconds())
            if 0 <= idx < len(values_failed):
                ip = ev.get("ip")
                if typ == "failed":
                    values_failed[idx] += 1
                    if ip:
                        failed_bucket_ips[idx][ip] += 1
                elif typ == "accepted":
                    values_accepted[idx] += 1
                    if ip:
                        accepted_bucket_ips[idx][ip] += 1
        # convert ip dicts to sorted lists for transport
        def sort_items(dct):
            return sorted(dct.items(), key=lambda x: x[1], reverse=True)
        failed_ips_list = [sort_items(d) for d in failed_bucket_ips]
        accepted_ips_list = [sort_items(d) for d in accepted_bucket_ips]
        return {"labels": labels, "failed": values_failed, "accepted": values_accepted, "failed_ips": failed_ips_list, "accepted_ips": accepted_ips_list}

    @app.get("/api/ssh/summary")
    @login_required
    def api_ssh_summary():
        since_raw = request.args.get("since", "24h")
        since_norm, window_secs = _normalize_since(since_raw)
        ok, data, err = ssh_service.fetch_and_analyze(since=since_norm, max_lines=10000)
        if not ok:
            return {"ok": False, "error": err}, 500
        geo_failed = geo_service.geolocate_many(data.get("top_failed_ips", []))
        # Build series from full set of events (not truncated for UI)
        ok_lines, lines, _err_lines = ssh_service.fetch_raw_lines(since=since_norm, max_lines=10000)
        evs_full = ssh_service.parse_events(lines) if ok_lines else data.get("events", [])
        series = _build_timeseries(evs_full, window_secs)
        f2b = _gather_f2b_metrics()
        def _aggregate_banned_ips(metrics: dict) -> list[tuple[str,int]]:
            from collections import Counter
            c = Counter()
            for m in (metrics or {}).values():
                for ip in m.get("banned_list", []) or []:
                    if is_valid_ip(ip):
                        c[ip] += 1
            return list(c.items())
        banned_tuples = _aggregate_banned_ips(f2b.get("metrics", {}))
        geo_banned = geo_service.geolocate_many(banned_tuples)
        return {"ok": True, "data": data, "geo_failed": geo_failed, "geo_banned": geo_banned, "series": series, "f2b": f2b}

    @app.get("/config")
    @login_required
    def config_index():
        okf, content, errf, codef = service.read_config_file(defaults_path)
        if not okf:
            flash(f"Attention: fichier non lisible: {defaults_path} ({errf}). Vérifiez les permissions.", "warning")
        ok, out, err, code = service.status()
        if not ok:
            flash(f"Erreur statut global: {err or out}", "danger")
            return render_template("config.html", jails=[], options={})
        jails = parse_global_status(out).get("jails", [])
        options = {}
        for j in jails:
            okj, vals, errj, codej = service.get_jail_options(j, ["bantime", "findtime", "maxretry"])
            options[j] = vals if okj else {}
        return render_template("config.html", jails=jails, options=options)

    @app.get("/config/<jail>")
    @login_required
    def config_jail(jail):
        ok, vals, err, code = service.get_jail_options(jail, ["bantime", "findtime", "maxretry"])
        if not ok:
            flash(f"Erreur lecture options {jail}: {err}", "danger")
            vals = {}
        return render_template("config_jail.html", jail=jail, values=vals, defaults_path=defaults_path)

    @app.post("/config/<jail>")
    @login_required
    def config_jail_save(jail):
        bantime = request.form.get("bantime", "").strip()
        findtime = request.form.get("findtime", "").strip()
        maxretry = request.form.get("maxretry", "").strip()
        to_set = {}
        errors = []
        import re
        def valid_val(v):
            return bool(re.fullmatch(r"\d+[smhdw]?", v))
        if bantime:
            if valid_val(bantime):
                to_set["bantime"] = bantime
            else:
                errors.append("bantime invalide (ex: 600, 10m, 1h)")
        if findtime:
            if valid_val(findtime):
                to_set["findtime"] = findtime
            else:
                errors.append("findtime invalide (ex: 600, 10m, 1h)")
        if maxretry:
            if maxretry.isdigit() and int(maxretry) >= 1:
                to_set["maxretry"] = maxretry
            else:
                errors.append("maxretry doit être un entier >= 1")
        if errors:
            for e in errors:
                flash(e, "warning")
        if to_set:
            ok, msg, code = service.set_jail_options(jail, to_set)
            if ok:
                flash("Paramètres enregistrés (runtime).", "success")
            else:
                flash(f"Erreur enregistrement runtime: {msg}", "danger")
        elif not errors:
            flash("Aucun paramètre à enregistrer.", "info")
        if to_set:
            ok_cp, cp, err_cp, code_cp = service.read_jail_conf(defaults_path)
            if not ok_cp or cp is None:
                cp = configparser.ConfigParser(strict=False, interpolation=None)
            section = jail
            if not cp.has_section(section):
                cp.add_section(section)
            for k, v in to_set.items():
                cp.set(section, k, str(v))
            ok_w, msg_w, code_w = service.write_jail_conf(defaults_path, cp, backup=True)
            if ok_w:
                flash(f"Paramètres enregistrés dans {defaults_path}.", "success")
            else:
                flash(f"Erreur écriture persistante dans {defaults_path}: {msg_w}", "danger")
        return redirect(url_for("config_jail", jail=jail))

    @app.errorhandler(404)
    def handle_404(e):
        try:
            # Keep 404 for static assets to avoid breaking CSS/JS
            if request.path.startswith('/static'):
                return e, 404
        except Exception:
            pass
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG", "0") == "1")
