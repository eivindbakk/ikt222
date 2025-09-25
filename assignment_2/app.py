@app.route("/feed")
def feed_vuln():
    """
    Vulnerable feed — visually identical to /feed-safe (same layout, sidebar, trending, who-to-follow),
    but post content is rendered UNSAFE (Markup of raw content) to demonstrate stored XSS.
    """
    db = get_db()
    uid = session.get("uid", -1)

    # Get posts with counts (same query as feed_safe)
    rows = db.execute("""
        SELECT p.id, p.content, p.created_at, u.username,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) as like_count,
               EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) as i_like,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) as comment_count
        FROM posts p
        JOIN users u ON p.user_id=u.id
        ORDER BY p.id DESC LIMIT 100
    """, (uid,)).fetchall()

    posts = []
    for r in rows:
        posts.append({
            "id": r["id"],
            "username": r["username"],
            "created_at": r["created_at"],
            # INTENTIONALLY UNSAFE: render raw content (stored XSS demonstration)
            "content_html": Markup(r["content"]),
            "like_count": r["like_count"],
            "i_like": bool(r["i_like"]),
            "comment_count": r["comment_count"]
        })

    # Sidebar: trending tags (same heuristic) and who-to-follow
    trending = db.execute("""
        SELECT LOWER(substr(tag,2)) AS tag, COUNT(*) as cnt
        FROM (
          SELECT substr(value, instr(value, '#')) AS tag
          FROM (
            SELECT replace(replace(content, '\n', ' '), '\r', ' ') AS content FROM posts
          ), json_each('["' || replace(content, ' ', '","') || '"]')
          WHERE value LIKE '#%'
        )
        GROUP BY LOWER(tag)
        ORDER BY cnt DESC LIMIT 8
    """).fetchall()

    who = db.execute("""
        SELECT u.username FROM users u
        WHERE u.id != ? AND u.id NOT IN (SELECT followee_id FROM follows WHERE follower_id=?)
        ORDER BY u.id DESC LIMIT 5
    """, (uid, uid)).fetchall()

    me = current_user()
    # Render the exact same template as the safe feed so both pages look identical.
    # We pass vulnerable=True so the template can show a visible warning / badge.
    return render_template(
        "timeline_safe.html",
        posts=posts,
        me=me,
        trending=[dict(t) for t in trending],
        who=[dict(w) for w in who],
        vulnerable=True
    )
