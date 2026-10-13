"""The problem statement's rules + worked example (M.Sc. DFIS)."""
from datetime import date

from app import clock

from .conftest import make_student, new_asset_item, new_qty_item, stock


def issue(client, who, student_id, lines, issue_date=None, purpose="Lab project"):
    body = {"student_id": student_id, "purpose": purpose, "lines": lines}
    if issue_date:
        body["issue_date"] = issue_date
    return client.post("/issues", headers=who["h"], json=body)


def test_worked_example(client, coord, staff, student):
    clock.set_today(date(2026, 10, 1))
    board_item, boards = new_asset_item(client, coord, n=10)
    cable = new_qty_item(client, coord, qty=20)
    assert stock(client, coord, board_item["id"])["available"] == 10

    r = issue(client, staff, student["id"], [{"item_id": board_item["id"], "asset_id": boards[0]["id"]}, {"item_id": cable["id"], "quantity": 2}])
    assert r.status_code == 201, r.text
    ack = r.json()
    assert all(l["due_date"] == "2026-10-16" for l in ack["lines"])            # rule 5
    assert stock(client, coord, board_item["id"])["available"] == 9
    assert stock(client, coord, cable["id"])["available"] == 18

    mine = client.get("/me/issues", headers=student["h"]).json()                 # visible in the student's account
    assert {l["due_date"] for l in mine} == {"2026-10-16"} and len(mine) == 2
    cable_line = next(l for l in mine if l["item_code"] == cable["code"])
    board_line = next(l for l in mine if l["item_code"] == board_item["code"])

    # rule 7: requesting does NOT extend
    rq = client.post("/me/renewals", headers=student["h"], json={"line_id": board_line["line_id"]})
    assert rq.status_code == 201 and rq.json()["status"] == "PENDING"
    assert client.get("/me/issues", headers=student["h"]).json()[0]["due_date"] == "2026-10-16"
    # duplicate pending request refused
    assert client.post("/me/renewals", headers=student["h"], json={"line_id": board_line["line_id"]}).status_code == 409

    # staff (non-coordinator) cannot approve; coordinator can -> +15 days from existing due date (rule 8)
    assert client.post(f"/renewals/{rq.json()['id']}/decision", headers=staff["h"], json={"approve": True}).status_code == 403
    d = client.post(f"/renewals/{rq.json()['id']}/decision", headers=coord["h"], json={"approve": True, "remarks": "approved"})
    assert d.status_code == 200 and d.json()["revised_due"] == "2026-10-31"

    # partial return of cables (rule 11)
    pr = client.post(f"/issue-lines/{cable_line['line_id']}/return", headers=staff["h"], json={"quantity": 1, "condition": "GOOD"})
    assert pr.status_code == 200 and pr.json()["outstanding"] == 1 and pr.json()["status"] == "OPEN"
    assert stock(client, coord, cable["id"])["available"] == 19 and stock(client, coord, cable["id"])["issued"] == 1
    # cannot return more than outstanding
    assert client.post(f"/issue-lines/{cable_line['line_id']}/return", headers=staff["h"], json={"quantity": 5, "condition": "GOOD"}).status_code == 409

    # cable (not renewed) goes overdue after 16 Oct; board (renewed) does not
    clock.set_today(date(2026, 10, 19))
    od = client.get("/overdue", headers=staff["h"]).json()
    mine_od = [o for o in od if o["student_id"] == student["id"]]
    assert len(mine_od) == 1 and mine_od[0]["overdue_days"] == 3 and mine_od[0]["outstanding"] == 1
    assert "overdue by three days" in mine_od[0]["message"] and student["enrol"] in mine_od[0]["message"]
    assert "overdue" in client.get("/me/reminders", headers=student["h"]).json()["overdue"][0]

    # return board in good condition -> available again (rule 9)
    assert client.post(f"/issue-lines/{board_line['line_id']}/return", headers=staff["h"], json={"quantity": 1, "condition": "GOOD"}).status_code == 200
    assert stock(client, coord, board_item["id"])["available"] == 10


def test_not_enough_stock_message_and_no_side_effects(client, coord, staff, student):
    adapter = new_qty_item(client, coord, qty=3, name="Adapter")
    cable = new_qty_item(client, coord, qty=10)
    r = issue(client, staff, student["id"], [{"item_id": cable["id"], "quantity": 2}, {"item_id": adapter["id"], "quantity": 5}])
    assert r.status_code == 409
    assert "Five Adapters were requested, but only three are currently available." in r.json()["detail"]
    # atomic: the cable line that WOULD have succeeded was rolled back
    assert stock(client, coord, cable["id"])["available"] == 10
    assert stock(client, coord, adapter["id"])["available"] == 3
    assert client.get("/me/issues", headers=student["h"]).json() == []


def test_asset_cannot_be_double_issued(client, coord, staff):
    item, assets = new_asset_item(client, coord, n=1)
    s1, s2 = make_student(client, coord), make_student(client, coord)
    assert issue(client, staff, s1["id"], [{"item_id": item["id"], "asset_id": assets[0]["id"]}]).status_code == 201
    r = issue(client, staff, s2["id"], [{"item_id": item["id"], "asset_id": assets[0]["id"]}])
    assert r.status_code == 409 and "already issued" in r.json()["detail"]


def test_only_registered_students(client, coord, staff):
    item = new_qty_item(client, coord)
    assert issue(client, staff, 999999, [{"item_id": item["id"]}]).status_code == 422
    assert stock(client, coord, item["id"])["available"] == 20


def test_damaged_return_stays_unavailable_until_coordinator_updates(client, coord, staff, student):
    item, assets = new_asset_item(client, coord, n=1)
    ln = issue(client, staff, student["id"], [{"item_id": item["id"], "asset_id": assets[0]["id"]}]).json()["lines"][0]
    client.post(f"/issue-lines/{ln['line_id']}/return", headers=staff["h"], json={"quantity": 1, "condition": "DAMAGED", "remarks": "cracked"})
    s = stock(client, coord, item["id"])
    assert s["available"] == 0 and s["damaged"] == 1
    s2 = make_student(client, coord)
    r = issue(client, staff, s2["id"], [{"item_id": item["id"], "asset_id": assets[0]["id"]}])
    assert r.status_code == 409 and "unavailable" in r.json()["detail"]
    # staff cannot restore it; coordinator can (rule 10)
    assert client.post(f"/assets/{assets[0]['id']}/status", headers=staff["h"], json={"status": "AVAILABLE", "reason": "repaired"}).status_code == 403
    assert client.post(f"/assets/{assets[0]['id']}/status", headers=coord["h"], json={"status": "AVAILABLE", "reason": "repaired"}).status_code == 200
    assert issue(client, staff, s2["id"], [{"item_id": item["id"], "asset_id": assets[0]["id"]}]).status_code == 201


def test_quantity_damaged_and_lost_buckets(client, coord, staff, student):
    item = new_qty_item(client, coord, qty=10)
    ln = issue(client, staff, student["id"], [{"item_id": item["id"], "quantity": 4}]).json()["lines"][0]
    for q, cond in ((1, "DAMAGED"), (1, "LOST"), (1, "NEEDS_MAINTENANCE"), (1, "GOOD")):
        assert client.post(f"/issue-lines/{ln['line_id']}/return", headers=staff["h"], json={"quantity": q, "condition": cond}).status_code == 200
    s = stock(client, coord, item["id"])
    assert (s["total"], s["available"], s["issued"], s["damaged"], s["lost"], s["maintenance"]) == (10, 7, 0, 1, 1, 1)


def test_renewal_rules(client, coord, staff, student):
    clock.set_today(date(2026, 10, 1))
    item = new_qty_item(client, coord)
    ln = issue(client, staff, student["id"], [{"item_id": item["id"], "quantity": 1}], issue_date="2026-10-01").json()["lines"][0]
    # reject needs remarks; rejection leaves due date alone
    rq = client.post("/me/renewals", headers=student["h"], json={"line_id": ln["line_id"]}).json()
    assert client.post(f"/renewals/{rq['id']}/decision", headers=coord["h"], json={"approve": False}).status_code == 422
    rj = client.post(f"/renewals/{rq['id']}/decision", headers=coord["h"], json={"approve": False, "remarks": "need it back"}).json()
    assert rj["status"] == "REJECTED" and rj["revised_due"] is None
    assert client.get("/me/issues", headers=student["h"]).json()[0]["due_date"] == "2026-10-16"
    # limit of 2 approved renewals (default policy)
    for expected in ("2026-10-31", "2026-11-15"):
        rq = client.post("/me/renewals", headers=student["h"], json={"line_id": ln["line_id"]}).json()
        assert client.post(f"/renewals/{rq['id']}/decision", headers=coord["h"], json={"approve": True}).json()["revised_due"] == expected
    assert client.post("/me/renewals", headers=student["h"], json={"line_id": ln["line_id"]}).status_code == 409
    # after the due date renewal requests are refused
    item2 = new_qty_item(client, coord)
    s2 = make_student(client, coord)
    l2 = issue(client, staff, s2["id"], [{"item_id": item2["id"]}], issue_date="2026-10-01").json()["lines"][0]
    clock.set_today(date(2026, 10, 17))
    r = client.post("/me/renewals", headers=s2["h"], json={"line_id": l2["line_id"]})
    assert r.status_code == 409 and "due date has passed" in r.json()["detail"]


def test_overdue_student_blocked_from_new_issue(client, coord, staff, student):
    clock.set_today(date(2026, 10, 1))
    item = new_qty_item(client, coord)
    issue(client, staff, student["id"], [{"item_id": item["id"]}])
    clock.set_today(date(2026, 10, 20))
    r = issue(client, staff, student["id"], [{"item_id": item["id"]}])
    assert r.status_code == 409 and "overdue" in r.json()["detail"]


def test_stock_adjustments_need_reason_and_cannot_break_books(client, coord, staff):
    item = new_qty_item(client, coord, qty=5)
    adj = lambda **b: client.post(f"/items/{item['id']}/adjust", headers=coord["h"], json=b)  # noqa: E731
    assert adj(action="ADD", quantity=5, reason="purchase").json()["total"] == 10
    assert adj(action="ADD", quantity=5).status_code == 422                        # reason mandatory
    assert adj(action="RETIRE", bucket="AVAILABLE", quantity=100, reason="x y z").status_code == 409
    assert adj(action="MOVE", bucket="AVAILABLE", to_bucket="MAINTENANCE", quantity=2, reason="loose pins").json()["maintenance"] == 2
    assert adj(action="CORRECT", bucket="AVAILABLE", quantity=-1, reason="miscount").json()["total"] == 9
    assert client.post(f"/items/{item['id']}/adjust", headers=staff["h"], json={"action": "ADD", "quantity": 1, "reason": "nope"}).status_code == 403
    s = stock(client, coord, item["id"])
    assert s["total"] == s["available"] + s["issued"] + s["damaged"] + s["lost"] + s["maintenance"]


def test_reports_and_csv_formula_guard(client, coord, staff, student):
    item = new_qty_item(client, coord, name="=HYPERLINK(\"http://evil\")")
    issue(client, staff, student["id"], [{"item_id": item["id"]}])
    r = client.get(f"/reports/transactions?item_id={item['id']}&format=csv", headers=coord["h"])
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "'=HYPERLINK" in r.text and ",=HYPERLINK" not in r.text
    j = client.get(f"/reports/transactions?student_id={student['id']}", headers=coord["h"]).json()
    assert any(e["event"] == "ISSUE" for e in j)
    assert client.get("/reports/transactions?programme=M.Sc.%20DFIS", headers=coord["h"]).status_code == 200
