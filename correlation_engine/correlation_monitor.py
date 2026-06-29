#!/usr/bin/env python3
"""
================================================================================
SMART SIEM — Moniteur temps réel du moteur de corrélation
================================================================================
Rôle        : Interface Rich en temps réel qui affiche :
              - Les alertes générées par correlation_engine (depuis PostgreSQL)
              - Les logs ingérés dans Elasticsearch (statistiques)
              - Le détail de chaque alerte : règle, preuves, confidence, playbooks
              - Les niveaux de criticité avec codes couleur
              - Les playbooks associés à chaque alerte

Architecture :
  Ce moniteur est INDÉPENDANT du moteur de corrélation.
  Il lit directement dans PostgreSQL (table alerts, correlation_rules, playbooks)
  et dans Elasticsearch (comptage des logs récents).
  On peut donc lancer :
    Terminal 1 : python3 attack_simulator.py    (génère les logs d'attaque)
    Terminal 2 : python3 correlation_engine.py  (détecte et génère les alertes)
    Terminal 3 : python3 correlation_monitor.py (affiche les résultats en temps réel)

Refresh    : toutes les 3 secondes
Navigation : touches clavier pour filtrer par niveau / trier
================================================================================
"""

import os, json, asyncio, asyncpg
from datetime import datetime, timezone, timedelta
from elasticsearch import AsyncElasticsearch
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.rule import Rule
from rich.columns import Columns
from rich import box
from rich.align import Align
from rich.spinner import Spinner
from rich.progress import BarColumn, Progress

# ── Configuration ─────────────────────────────────────────────────────────────
ES_HOST     = os.environ.get("ES_HOST",     "https://localhost:9200")
ES_USER     = os.environ.get("ES_USER",     "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "8-0Il66xvSeGnK=COySu")
ES_CACERT   = os.environ.get("ES_CACERT",   "http_ca.crt")
ES_INDEX    = "siem-logs-*"
PG_DSN      = os.environ.get("PG_DSN",
    "postgresql://postgres:felicia@localhost:5432/nafeh")

REFRESH_SEC = 3       # Fréquence de rafraîchissement
MAX_ALERTS  = 20      # Nombre d'alertes affichées
console = Console()

# ── Codes couleur par niveau d'alerte ─────────────────────────────────────────
LEVEL_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "WARNING":  "bold yellow",
    "INFO":     "dim white",
}
LEVEL_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "WARNING":  "🟡",
    "INFO":     "⚪",
}
STATUS_STYLE = {
    "open":          "bold red",
    "investigating": "bold yellow",
    "confirmed":     "bold orange1",
    "false_positive":"dim white",
    "escalated":     "bold magenta",
    "closed":        "dim green",
}


# ── Requêtes base de données ───────────────────────────────────────────────────

async def fetch_alerts(pool: asyncpg.Pool,
                       filter_level: str = None,
                       sort_asc: bool = False,
                       limit: int = MAX_ALERTS) -> list[dict]:
    """
    Charge les alertes depuis PostgreSQL avec les informations enrichies :
    - Nom de la règle déclenchée
    - Playbook(s) associé(s)
    - Score de confiance
    - Preuves (IDs des logs ES corrélés)
    """
    order = "ASC" if sort_asc else "DESC"
    conditions = ""
    params = [limit]
    if filter_level:
        params.insert(0, filter_level)
        conditions = f"AND a.level = ${len(params)-1}::alert_level"

    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT
                a.id,
                a.title,
                a.level::text,
                a.status::text,
                a.triggered_at,
                a.acknowledged_at,
                a.confidence_score,
                a.mitre_tactic,
                a.correlated_event_ids::text,
                a.source_ips::text,
                a.affected_hosts::text,
                a.usernames::text,
                a.is_false_positive,
                a.notes,
                r.name          AS rule_name,
                r.rule_type     AS rule_type,
                r.time_window_seconds,
                r.threshold_count,
                r.mitre_technique,
                p.name          AS playbook_name,
                p.execution_mode::text AS playbook_mode,
                p.action_type   AS playbook_action
            FROM alerts a
            JOIN correlation_rules r ON r.id = a.rule_id
            LEFT JOIN playbooks p    ON p.id = r.playbook_id
            WHERE 1=1 {conditions}
            ORDER BY a.triggered_at {order}
            LIMIT ${len(params)}
        """, *params)
    return [dict(r) for r in rows]


async def fetch_alert_stats(pool: asyncpg.Pool) -> dict:
    """Statistiques globales des alertes."""
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM alerts")
        by_level = await conn.fetch(
            "SELECT level::text, COUNT(*) as cnt FROM alerts "
            "GROUP BY level ORDER BY cnt DESC"
        )
        by_status = await conn.fetch(
            "SELECT status::text, COUNT(*) as cnt FROM alerts "
            "GROUP BY status ORDER BY cnt DESC"
        )
        open_critical = await conn.fetchval(
            "SELECT COUNT(*) FROM alerts WHERE level='CRITICAL' AND status='open'"
        )
        last_alert_time = await conn.fetchval(
            "SELECT triggered_at FROM alerts ORDER BY triggered_at DESC LIMIT 1"
        )
        active_rules = await conn.fetchval(
            "SELECT COUNT(*) FROM correlation_rules WHERE is_active=TRUE"
        )
    return {
        "total":          total,
        "by_level":       {r["level"]: r["cnt"] for r in by_level},
        "by_status":      {r["status"]: r["cnt"] for r in by_status},
        "open_critical":  open_critical,
        "last_alert_at":  last_alert_time,
        "active_rules":   active_rules,
    }


async def fetch_es_stats(es: AsyncElasticsearch) -> dict:
    """Statistiques Elasticsearch : comptages par period."""
    now = datetime.now(timezone.utc)
    try:
        # Total logs
        total_r = await es.count(index=ES_INDEX)
        total   = total_r["count"]

        # Logs de la dernière minute
        last_min = await es.count(index=ES_INDEX, body={
            "query": {"range": {"@timestamp": {
                "gte": (now - timedelta(minutes=1)).isoformat()
            }}}
        })

        # Logs des 5 dernières minutes
        last_5m = await es.count(index=ES_INDEX, body={
            "query": {"range": {"@timestamp": {
                "gte": (now - timedelta(minutes=5)).isoformat()
            }}}
        })

        # Répartition par severity (dernière heure)
        sev_agg = await es.search(index=ES_INDEX, body={
            "query": {"range": {"@timestamp": {
                "gte": (now - timedelta(hours=1)).isoformat()
            }}},
            "aggs": {"by_sev": {"terms": {"field": "severity", "size": 10}}},
            "size": 0
        })
        by_sev = {
            b["key"]: b["doc_count"]
            for b in sev_agg["aggregations"]["by_sev"]["buckets"]
        }

        # Top event_actions (dernière heure)
        act_agg = await es.search(index=ES_INDEX, body={
            "query": {"range": {"@timestamp": {
                "gte": (now - timedelta(hours=1)).isoformat()
            }}},
            "aggs": {"by_action": {"terms": {"field": "event_action", "size": 8}}},
            "size": 0
        })
        top_actions = [
            (b["key"], b["doc_count"])
            for b in act_agg["aggregations"]["by_action"]["buckets"]
        ]

        return {
            "total":       total,
            "last_1min":   last_min["count"],
            "last_5min":   last_5m["count"],
            "by_severity": by_sev,
            "top_actions": top_actions,
        }
    except Exception as e:
        return {"error": str(e), "total": 0, "last_1min": 0,
                "last_5min": 0, "by_severity": {}, "top_actions": []}


# ── Constructeurs de panels Rich ───────────────────────────────────────────────

def build_header(stats: dict, es_stats: dict, sort_asc: bool,
                 filter_level: str, refresh_count: int) -> Panel:
    """Bandeau supérieur avec les KPIs."""
    now_str = datetime.now().strftime("%H:%M:%S")
    crit = stats.get("open_critical", 0)
    crit_text = f"[bold red]🚨 {crit} CRITICAL ouverts[/bold red]" if crit > 0 \
                else "[green]✓ Aucun CRITICAL ouvert[/green]"

    last_alert = stats.get("last_alert_at")
    last_str = last_alert.strftime("%H:%M:%S") if last_alert else "—"

    cols = Columns([
        Panel(
            f"[bold]{stats.get('total', 0)}[/bold]\nAlertes totales",
            style="blue", box=box.ROUNDED, width=18, padding=(0, 1)
        ),
        Panel(
            f"{crit_text}\nDernière : {last_str}",
            box=box.ROUNDED, width=30, padding=(0, 1)
        ),
        Panel(
            f"[bold]{es_stats.get('total', 0)}[/bold] logs ES\n"
            f"+[green]{es_stats.get('last_1min', 0)}[/green]/min  "
            f"+[yellow]{es_stats.get('last_5min', 0)}[/yellow]/5min",
            box=box.ROUNDED, width=28, padding=(0, 1)
        ),
        Panel(
            f"[bold]{stats.get('active_rules', 0)}[/bold] règles actives\n"
            f"Refresh #{refresh_count} à {now_str}",
            box=box.ROUNDED, width=28, padding=(0, 1)
        ),
    ], equal=False, expand=False)

    filter_info = f"  [dim]Filtre: {filter_level or 'tous'}  |  "
    filter_info += f"Tri: {'ancien→récent' if sort_asc else 'récent→ancien'}[/dim]"

    return Panel(cols, title="[bold blue]⚡ SMART SIEM — Moniteur temps réel[/bold blue]",
                 subtitle=filter_info, box=box.DOUBLE_EDGE, style="blue")


def build_alerts_table(alerts: list[dict]) -> Table:
    """
    Table principale des alertes avec toutes les colonnes importantes.
    Chaque ligne = une alerte avec son contexte complet.
    """
    t = Table(
        box=box.SIMPLE_HEAD,
        show_lines=True,
        expand=True,
        header_style="bold blue",
        row_styles=["", "dim"],
    )
    t.add_column("Heure",       style="dim",   width=8,  no_wrap=True)
    t.add_column("Niveau",      style="bold",  width=10, no_wrap=True)
    t.add_column("Statut",      width=14,      no_wrap=True)
    t.add_column("Titre / Règle",              min_width=30)
    t.add_column("MITRE",       width=8,       no_wrap=True)
    t.add_column("Conf%",       width=6,       no_wrap=True, justify="right")
    t.add_column("Type règle",  width=11,      no_wrap=True)
    t.add_column("Preuves",     width=6,       no_wrap=True, justify="right")
    t.add_column("Playbook",    width=22,      no_wrap=True)

    for a in alerts:
        level     = a.get("level", "INFO")
        status    = a.get("status", "open")
        style     = LEVEL_STYLE.get(level, "white")
        icon      = LEVEL_ICON.get(level, "•")
        conf      = a.get("confidence_score") or 0
        mitre     = a.get("mitre_tactic") or "—"
        rule_type = a.get("rule_type") or "—"

        # Timestamp local
        ts = a.get("triggered_at")
        ts_str = ts.strftime("%H:%M:%S") if ts else "—"

        # Titre (première ligne) + nom de règle (deuxième ligne)
        title_text = Text(overflow="fold")
        title_text.append(a.get("title", "")[:55], style=style)
        title_text.append(f"\n  ↳ {a.get('rule_name', '')}", style="dim")

        # Nombre de preuves (IDs de logs ES corrélés)
        proofs_raw = a.get("correlated_event_ids", "[]")
        try:
            proof_count = len(json.loads(proofs_raw or "[]"))
        except Exception:
            proof_count = 0

        # Playbook associé
        pb_name = a.get("playbook_name")
        pb_mode = a.get("playbook_mode", "")
        if pb_name:
            pb_color = "green" if pb_mode == "AUTO" else "yellow"
            pb_text = Text()
            pb_text.append(pb_name, style=f"bold {pb_color}")
            pb_text.append(f" ({pb_mode})", style="dim")
        else:
            pb_text = Text("—", style="dim")

        # Score de confiance coloré
        if conf >= 85:
            conf_str = f"[green]{conf}[/green]"
        elif conf >= 70:
            conf_str = f"[yellow]{conf}[/yellow]"
        else:
            conf_str = f"[red]{conf}[/red]"

        # Statut coloré
        status_style = STATUS_STYLE.get(status, "white")
        status_text = Text(status, style=status_style)

        t.add_row(
            ts_str,
            Text(f"{icon} {level}", style=style),
            status_text,
            title_text,
            Text(mitre, style="cyan"),
            Text(conf_str, style=""),
            Text(rule_type, style="magenta"),
            Text(str(proof_count), style="blue"),
            pb_text,
        )

    if not alerts:
        t.add_row(
            "—", "—", "—",
            Text("Aucune alerte — en attente de détections...", style="dim italic"),
            "—", "—", "—", "—", "—"
        )

    return t


def build_alert_detail(alert: dict) -> Panel:
    """
    Panel de détail pour l'alerte la plus récente.
    Affiche : preuves ES, IPs, hosts, username, explication.
    """
    if not alert:
        return Panel("[dim]Aucune alerte à détailler[/dim]",
                     title="Détail alerte", box=box.ROUNDED)

    level  = alert.get("level", "INFO")
    style  = LEVEL_STYLE.get(level, "white")
    icon   = LEVEL_ICON.get(level, "•")

    # Parsing des champs JSON
    def parse_list(raw):
        try:
            return json.loads(raw or "[]") if isinstance(raw, str) else (raw or [])
        except Exception:
            return []

    ips      = parse_list(alert.get("source_ips"))
    hosts    = parse_list(alert.get("affected_hosts"))
    users    = parse_list(alert.get("usernames"))
    proof_ids= parse_list(alert.get("correlated_event_ids"))

    # Explication du déclenchement
    rule_type   = alert.get("rule_type", "")
    threshold   = alert.get("threshold_count")
    window      = alert.get("time_window_seconds")
    technique   = alert.get("mitre_technique") or ""

    if rule_type == "threshold":
        explain = (f"Règle seuil : {threshold}+ occurrences "
                   f"en {window}s → {level}")
    elif rule_type == "pattern":
        explain = f"Règle séquentielle : kill-chain détectée en {window}s"
    elif rule_type == "composite":
        explain = f"Règle composite : corrélation inter-sources en {window}s"
    else:
        explain = f"Règle {rule_type}"

    # Pourquoi cette alerte ? (attestation)
    attestation = (
        f"{len(proof_ids)} log(s) ES corrélé(s) constituent les preuves.\n"
        f"Technique MITRE : {technique or '—'}  |  "
        f"Confiance : {alert.get('confidence_score', 0)}%"
    )

    content = Text()
    content.append(f"{icon} {alert.get('title', '')}\n", style=f"bold {style}")
    content.append(f"\n📋 Règle     : ", style="bold")
    content.append(f"{alert.get('rule_name', '')}\n")
    content.append(f"⚙️  Type      : ", style="bold")
    content.append(f"{explain}\n")
    content.append(f"🎯 MITRE     : ", style="bold")
    content.append(f"{alert.get('mitre_tactic', '—')} / {technique or '—'}\n")
    content.append(f"\n🔍 Pourquoi  : ", style="bold yellow")
    content.append(f"{attestation}\n")
    content.append(f"\n🌐 IPs       : ", style="bold")
    content.append(f"{', '.join(ips) or '—'}\n")
    content.append(f"🖥  Hosts     : ", style="bold")
    content.append(f"{', '.join(hosts) or '—'}\n")
    content.append(f"👤 Users     : ", style="bold")
    content.append(f"{', '.join(users) or '—'}\n")
    content.append(f"\n📎 Preuves ES: ", style="bold blue")
    content.append(f"{len(proof_ids)} log(s) corrélé(s)\n")
    if proof_ids:
        content.append("   IDs : " + ", ".join(str(p) for p in proof_ids[:3]))
        if len(proof_ids) > 3:
            content.append(f" ...+{len(proof_ids)-3}")
    content.append(f"\n\n🤖 Playbook  : ", style="bold green")
    pb = alert.get("playbook_name")
    if pb:
        mode = alert.get("playbook_mode", "")
        action = alert.get("playbook_action", "")
        color = "green" if mode == "AUTO" else "yellow"
        content.append(f"{pb}  ", style=f"bold {color}")
        content.append(f"[mode={mode}]  action={action}", style="dim")
    else:
        content.append("Aucun playbook associé", style="dim")

    return Panel(
        content,
        title=f"[bold {style}]Détail — alerte la plus récente[/bold {style}]",
        box=box.ROUNDED,
        style=style if level == "CRITICAL" else "white",
    )


def build_es_panel(es_stats: dict) -> Panel:
    """Panel des statistiques Elasticsearch."""
    if "error" in es_stats:
        return Panel(f"[red]ES Error: {es_stats['error']}[/red]",
                     title="Elasticsearch", box=box.ROUNDED)

    t = Table(show_header=False, box=None, padding=(0, 1))
    t.add_column("Label", style="dim", width=20)
    t.add_column("Value", style="bold")

    t.add_row("Total logs",   str(es_stats.get("total", 0)))
    t.add_row("Dernière 1min", f"[green]+{es_stats.get('last_1min', 0)}[/green]")
    t.add_row("Dernières 5min", f"[yellow]+{es_stats.get('last_5min', 0)}[/yellow]")

    by_sev = es_stats.get("by_severity", {})
    if by_sev:
        t.add_row("", "")
        t.add_row("[bold]Par sévérité[/bold]", "")
        for sev, cnt in sorted(by_sev.items(), key=lambda x: -x[1]):
            color = {"critical": "red", "high": "orange1",
                     "warning": "yellow", "info": "white"}.get(sev, "white")
            t.add_row(f"  {sev}", f"[{color}]{cnt}[/{color}]")

    top_acts = es_stats.get("top_actions", [])
    if top_acts:
        t.add_row("", "")
        t.add_row("[bold]Top actions[/bold]", "")
        for action, cnt in top_acts[:6]:
            t.add_row(f"  {action[:20]}", str(cnt))

    return Panel(t, title="📊 Elasticsearch", box=box.ROUNDED, style="blue")


def build_level_breakdown(stats: dict) -> Panel:
    """Mini-panel de répartition par niveau d'alerte."""
    t = Table(show_header=False, box=None, padding=(0, 1))
    t.add_column("Level", width=10)
    t.add_column("Count", width=6, justify="right")

    by_level = stats.get("by_level", {})
    for level in ["CRITICAL", "HIGH", "WARNING", "INFO"]:
        cnt   = by_level.get(level, 0)
        style = LEVEL_STYLE.get(level, "white")
        icon  = LEVEL_ICON.get(level, "•")
        t.add_row(Text(f"{icon} {level}", style=style), str(cnt))

    by_status = stats.get("by_status", {})
    if by_status:
        t.add_row("", "")
        for status, cnt in by_status.items():
            style = STATUS_STYLE.get(status, "white")
            t.add_row(Text(status, style=style), str(cnt))

    return Panel(t, title="📈 Répartition", box=box.ROUNDED)


def build_controls() -> Panel:
    """Panneau des contrôles clavier."""
    controls = (
        "[bold cyan]Contrôles[/bold cyan]  "
        "[dim]q[/dim]=Quitter  "
        "[dim]c[/dim]=Filtrer CRITICAL  "
        "[dim]h[/dim]=Filtrer HIGH  "
        "[dim]a[/dim]=Tous  "
        "[dim]s[/dim]=Inverser tri  "
        "[dim]Ctrl+C[/dim]=Arrêter"
    )
    return Panel(controls, box=box.ROUNDED, style="dim", height=3)


def build_full_layout(alerts: list[dict], stats: dict, es_stats: dict,
                      sort_asc: bool, filter_level: str,
                      refresh_count: int) -> Layout:
    """
    Construit le layout complet de l'interface.
    Structure :
      ┌─────────────────────────────────────────────────┐
      │ HEADER — KPIs globaux                           │
      ├─────────────────────────────────────────────────┤
      │ TABLE ALERTES (principale)         │ ES STATS   │
      ├────────────────────────────────────┤            │
      │ DÉTAIL alerte + Playbook           │ BREAKDOWN  │
      ├─────────────────────────────────────────────────┤
      │ CONTROLS                                        │
      └─────────────────────────────────────────────────┘
    """
    layout = Layout()
    layout.split_column(
        Layout(name="header",  size=5),
        Layout(name="middle",  ratio=2),
        Layout(name="detail",  ratio=3),
        Layout(name="controls",size=3),
    )
    layout["middle"].split_row(
        Layout(name="alerts_table", ratio=3),
        Layout(name="right_col",    ratio=1),
    )
    layout["right_col"].split_column(
        Layout(name="es_panel",    ratio=2),
        Layout(name="breakdown",   ratio=1),
    )

    layout["header"].update(
        build_header(stats, es_stats, sort_asc, filter_level, refresh_count)
    )
    layout["alerts_table"].update(
        Panel(
            build_alerts_table(alerts[:10]),
            title=f"[bold]⚠ Alertes ({len(alerts)} affichées)[/bold]",
            box=box.ROUNDED,
        )
    )
    layout["es_panel"].update(build_es_panel(es_stats))
    layout["breakdown"].update(build_level_breakdown(stats))
    layout["detail"].update(
        build_alert_detail(alerts[0] if alerts else None)
    )
    layout["controls"].update(build_controls())

    return layout


# ── Boucle principale ──────────────────────────────────────────────────────────

async def monitor_loop(pool: asyncpg.Pool, es: AsyncElasticsearch):
    """
    Boucle de rafraîchissement toutes les REFRESH_SEC secondes.
    Gère les contrôles clavier via des flags de state.
    """
    sort_asc      = False   # tri décroissant par défaut (plus récent en premier)
    filter_level  = None    # pas de filtre par défaut
    refresh_count = 0
    running       = True

    # Gestion des touches clavier de façon simple via input non-bloquant
    import threading

    def keyboard_thread():
        nonlocal sort_asc, filter_level, running
        while running:
            try:
                ch = input()
                if ch.lower() == "q":
                    running = False
                elif ch.lower() == "c":
                    filter_level = "CRITICAL"
                elif ch.lower() == "h":
                    filter_level = "HIGH"
                elif ch.lower() == "a":
                    filter_level = None
                elif ch.lower() == "s":
                    sort_asc = not sort_asc
            except (EOFError, KeyboardInterrupt):
                running = False

    kb_thread = threading.Thread(target=keyboard_thread, daemon=True)
    kb_thread.start()

    with Live(console=console, refresh_per_second=1/REFRESH_SEC,
              screen=True) as live:
        while running:
            try:
                # Chargement des données
                alerts   = await fetch_alerts(pool, filter_level, sort_asc)
                stats    = await fetch_alert_stats(pool)
                es_stats = await fetch_es_stats(es)
                refresh_count += 1

                # Construction et affichage du layout
                layout = build_full_layout(
                    alerts, stats, es_stats,
                    sort_asc, filter_level, refresh_count
                )
                live.update(layout)

            except Exception as e:
                console.print(f"[red]Erreur moniteur : {e}[/red]")

            await asyncio.sleep(REFRESH_SEC)

    console.print("\n[bold green]Moniteur arrêté.[/bold green]")


# ── Point d'entrée ─────────────────────────────────────────────────────────────

async def main():
    console.print(Panel(
        "[bold blue]SMART SIEM — Moniteur de corrélation[/bold blue]\n"
        "[dim]Connexion aux bases de données...[/dim]",
        box=box.DOUBLE_EDGE
    ))

    try:
        pool = await asyncpg.create_pool(dsn=PG_DSN, min_size=2, max_size=5)
    except Exception as e:
        console.print(f"[red]✗ PostgreSQL : {e}[/red]")
        console.print("[dim]Vérifier PG_DSN et que PostgreSQL est démarré[/dim]")
        return

    try:
        es = AsyncElasticsearch(
            hosts=[ES_HOST], basic_auth=(ES_USER, ES_PASSWORD),
            ca_certs=ES_CACERT, verify_certs=True,
        )
        info = await es.info()
        console.print(f"[green]✓ ES {info['version']['number']}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Elasticsearch : {e}[/red]")
        await pool.close()
        return

    console.print("[dim]Tapez q+Entrée pour quitter, "
                  "c+Entrée pour filtrer CRITICAL, a+Entrée pour tout afficher[/dim]")
    await asyncio.sleep(1)

    try:
        await monitor_loop(pool, es)
    finally:
        await pool.close()
        await es.close()


if __name__ == "__main__":
    asyncio.run(main())