from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import services
from ..audit import audit
from ..db import get_db
from ..deps import coordinator, staff_any
from ..errors import BusinessError
from ..models import Asset, AssetStatus, Item, ItemKind, Location, User
from ..schemas import (PathId, QueryId, AdjustIn, AssetIn, AssetOut, AssetStatusIn, ItemIn, ItemOut, ItemPatchIn, LocationIn, LocationOut,
                       PolicyIn, PolicyOut)

router = APIRouter(tags=["inventory"])


def _check_location(db: Session, location_id: int | None):
    if location_id is not None and db.get(Location, location_id) is None:
        raise HTTPException(422, "Unknown location_id")


# ---- locations
@router.post("/locations", response_model=LocationOut, status_code=201)
def create_location(body: LocationIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    loc = Location(**body.model_dump())
    db.add(loc)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A location with this name already exists") from None
    audit(db, user, "LOCATION_CREATE", "location", loc.id)
    db.commit()
    return loc


@router.get("/locations", response_model=list[LocationOut])
def list_locations(user: User = Depends(staff_any), db: Session = Depends(get_db)):
    return db.scalars(select(Location).order_by(Location.name)).all()


@router.put("/locations/{loc_id}", response_model=LocationOut)
def update_location(loc_id: PathId, body: LocationIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    loc = db.get(Location, loc_id) or _404("Location")
    for k, v in body.model_dump().items():
        setattr(loc, k, v)
    try:
        audit(db, user, "LOCATION_UPDATE", "location", loc.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A location with this name already exists") from None
    return loc


def _404(what: str):
    raise HTTPException(404, f"{what} not found")


# ---- items
@router.post("/items", response_model=ItemOut, status_code=201)
def create_item(body: ItemIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    _check_location(db, body.location_id)
    return services.create_item(db, user, body)


@router.get("/items", response_model=list[ItemOut])
def list_items(user: User = Depends(staff_any), db: Session = Depends(get_db), category: str | None = Query(None, max_length=80),
               kind: ItemKind | None = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    q = select(Item).order_by(Item.code).limit(limit).offset(offset)
    if category:
        q = q.where(Item.category == category)
    if kind:
        q = q.where(Item.kind == kind)
    return db.scalars(q).all()


@router.get("/items/{item_id}", response_model=ItemOut)
def get_item(item_id: PathId, user: User = Depends(staff_any), db: Session = Depends(get_db)):
    return db.get(Item, item_id) or _404("Item")


@router.patch("/items/{item_id}", response_model=ItemOut)
def patch_item(item_id: PathId, body: ItemPatchIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    item = db.get(Item, item_id) or _404("Item")
    data = body.model_dump(exclude_unset=True)
    _check_location(db, data.get("location_id"))
    for k, v in data.items():
        setattr(item, k, v)
    audit(db, user, "ITEM_UPDATE", "item", item.id, {"fields": sorted(data)})
    db.commit()
    return item


@router.post("/items/{item_id}/adjust")
def adjust(item_id: PathId, body: AdjustIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    """New stock (ADD), status change (MOVE), retirement (RETIRE) or miscount fix (CORRECT) -- always with a reason."""
    item = db.get(Item, item_id) or _404("Item")
    services.adjust_item(db, user, item, body)
    return services.stock_summary(db, item_id=item.id)[0]


@router.delete("/items/{item_id}", status_code=200)
def retire_item(item_id: PathId, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    """Soft-retire the whole item (history is never deleted). Refused while anything is still issued."""
    item = db.get(Item, item_id) or _404("Item")
    row = services.stock_summary(db, item_id=item.id)[0]
    if row["issued"]:
        raise BusinessError("Cannot retire an item while units are issued; record their return first.")
    item.is_active = False
    audit(db, user, "ITEM_RETIRE", "item", item.id)
    db.commit()
    return {"retired": True}


# ---- assets
@router.post("/items/{item_id}/assets", response_model=AssetOut, status_code=201)
def create_asset(item_id: PathId, body: AssetIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    item = db.get(Item, item_id) or _404("Item")
    _check_location(db, body.location_id)
    return services.add_asset(db, user, item, body)


@router.get("/assets", response_model=list[AssetOut])
def list_assets(user: User = Depends(staff_any), db: Session = Depends(get_db), item_id: QueryId = None, status: AssetStatus | None = None,
                limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    q = select(Asset).order_by(Asset.asset_tag).limit(limit).offset(offset)
    if item_id:
        q = q.where(Asset.item_id == item_id)
    if status:
        q = q.where(Asset.status == status)
    return db.scalars(q).all()


@router.post("/assets/{asset_id}/status", response_model=AssetOut)
def asset_status(asset_id: PathId, body: AssetStatusIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id) or _404("Asset")
    return services.set_asset_status(db, user, asset, body)


# ---- policy
@router.get("/policy", response_model=PolicyOut)
def get_policy(user: User = Depends(staff_any), db: Session = Depends(get_db)):
    return services.get_policy(db)


@router.put("/policy", response_model=PolicyOut)
def put_policy(body: PolicyIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    p = services.get_policy(db)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(p, k, v)
    audit(db, user, "POLICY_UPDATE", "policy", 1, body.model_dump(exclude_none=True))
    db.commit()
    return p
