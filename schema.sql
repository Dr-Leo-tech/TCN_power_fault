-- TCN fault telemetry gateway. Run this whole file in the Supabase SQL editor.

create table substations (
  id serial primary key,
  name text not null unique,
  region text not null,
  lat numeric not null,   -- only used to place the dot on the grid map
  lng numeric not null
);

create table lines (
  id serial primary key,
  from_substation_id int not null references substations(id),
  to_substation_id int not null references substations(id),
  voltage_kv int not null check (voltage_kv in (132, 330)),
  check (from_substation_id <> to_substation_id)
);

create table fault_events (
  id bigserial primary key,
  line_id int not null references lines(id),
  event_time_utc timestamptz not null,
  duration_ms int not null check (duration_ms > 0)
);

create table fault_classifications (
  id bigserial primary key,
  event_id bigint not null unique references fault_events(id),
  band text not null check (band in ('transient','short','sustained','persistent')),
  severity_score int not null
);

create table cascading_faults (
  id bigserial primary key,
  detected_at timestamptz not null default now(),
  event_ids jsonb not null
);

-- composite index required by the brief
create index fault_events_line_time_idx on fault_events (line_id, event_time_utc);
create index fault_events_time_idx on fault_events (event_time_utc desc);

-- audit: a fault, once written, can never be edited or removed
create function block_fault_changes() returns trigger as $$
begin
  raise exception 'fault_events is an audit log and cannot be changed';
end;
$$ language plpgsql;

create trigger fault_events_immutable
  before update or delete on fault_events
  for each row execute function block_fault_changes();

create function band_for(ms int) returns text as $$
  select case
    when ms < 100 then 'transient'
    when ms < 1000 then 'short'
    when ms <= 60000 then 'sustained'
    else 'persistent'
  end;
$$ language sql immutable;

create function band_weight(b text) returns int as $$
  select case b when 'transient' then 1 when 'short' then 2
               when 'sustained' then 3 else 4 end;
$$ language sql immutable;

-- POST /rest/v1/rpc/ingest_fault is our "/faults/ingest"
create function ingest_fault(p_line_id int, p_event_time timestamptz, p_duration_ms int)
returns jsonb as $$
declare
  new_id bigint;
  new_band text;
  near_ids bigint[];
  line_count int;
  cascade_id bigint;
begin
  -- one writer at a time, so two faults arriving together cannot both miss each other
  perform pg_advisory_xact_lock(37);

  insert into fault_events (line_id, event_time_utc, duration_ms)
  values (p_line_id, p_event_time, p_duration_ms)
  returning id into new_id;

  new_band := band_for(p_duration_ms);

  -- every fault inside the 5 second window around this one, on a different line
  select array_agg(id) into near_ids
  from fault_events
  where id <> new_id
    and line_id <> p_line_id
    and event_time_utc between p_event_time - interval '5 seconds'
                           and p_event_time + interval '5 seconds';

  if near_ids is null then
    insert into fault_classifications (event_id, band, severity_score)
    values (new_id, new_band, band_weight(new_band));
    return jsonb_build_object('event_id', new_id, 'band', new_band, 'cascading', false);
  end if;

  select count(distinct line_id) + 1 into line_count
  from fault_events where id = any(near_ids) and line_id <> p_line_id;

  -- join an existing cascade if one of the neighbours is already in it
  select id into cascade_id from cascading_faults
  where exists (select 1 from jsonb_array_elements_text(event_ids) e
                where e::bigint = any(near_ids))
  limit 1;

  if cascade_id is null then
    insert into cascading_faults (event_ids)
    values (to_jsonb(near_ids || new_id)) returning id into cascade_id;
  else
    update cascading_faults
    set event_ids = to_jsonb(
      (select array_agg(distinct x) from unnest(
        array(select e::bigint from jsonb_array_elements_text(event_ids) e)
        || near_ids || new_id) x))
    where id = cascade_id;
  end if;

  insert into fault_classifications (event_id, band, severity_score)
  values (new_id, new_band, band_weight(new_band) * line_count);

  -- the neighbours now sit in a bigger cascade, so their score goes up too
  update fault_classifications fc
  set severity_score = band_weight(fc.band) * line_count
  where fc.event_id = any(near_ids);

  return jsonb_build_object('event_id', new_id, 'band', new_band,
                            'cascading', true, 'cascade_id', cascade_id,
                            'affected_lines', line_count);
end;
$$ language plpgsql security definer;

-- Dashboard read. Keyset paging: ask for rows older than p_before, never "all rows".
create function recent_faults(p_before timestamptz default now() + interval '1 day', p_limit int default 25)
returns table (id bigint, line_id int, event_time_utc timestamptz, duration_ms int,
               band text, severity_score int)
as $$
  select e.id, e.line_id, e.event_time_utc, e.duration_ms, c.band, c.severity_score
  from fault_events e join fault_classifications c on c.event_id = e.id
  where e.event_time_utc < p_before
  order by e.event_time_utc desc
  limit least(p_limit, 100);
$$ language sql stable;

-- SQL injection demo ----------------------------------------------------
-- VULNERABLE: the caller's text is glued straight into the query.
create function search_faults_unsafe(p_line_id text) returns setof fault_events as $$
begin
  return query execute 'select * from fault_events where line_id = ' || p_line_id;
end;
$$ language plpgsql;
-- exploit: p_line_id = '1 or 1=1'  -> returns every line's faults, not just line 1

-- PATCHED: typed parameter plus a bound value, the text is never parsed as SQL.
create function search_faults(p_line_id int) returns setof fault_events as $$
begin
  return query execute 'select * from fault_events where line_id = $1' using p_line_id;
end;
$$ language plpgsql;
-- the same '1 or 1=1' is now rejected as "invalid input syntax for type integer"

-- Access: the browser may read and call functions, nothing else
alter table substations enable row level security;
alter table lines enable row level security;
alter table fault_events enable row level security;
alter table fault_classifications enable row level security;
alter table cascading_faults enable row level security;
create policy read_all on substations for select using (true);
create policy read_all on lines for select using (true);
create policy read_all on fault_events for select using (true);
create policy read_all on fault_classifications for select using (true);
create policy read_all on cascading_faults for select using (true);

alter publication supabase_realtime add table fault_events, cascading_faults;

-- Sample grid (coordinates are approximate, for the map only)
insert into substations (name, region, lat, lng) values
  ('Egbin', 'Lagos', 6.57, 3.62), ('Ikeja West', 'Lagos', 6.62, 3.23),
  ('Benin', 'Edo', 6.34, 5.63), ('Osogbo', 'Osun', 7.77, 4.56),
  ('Jebba', 'Niger', 9.13, 4.82), ('Shiroro', 'Niger', 9.97, 6.83),
  ('Kaduna', 'Kaduna', 10.52, 7.44);
insert into lines (from_substation_id, to_substation_id, voltage_kv) values
  (1,2,330), (2,4,330), (4,5,330), (5,6,330), (6,7,330), (3,4,330), (1,3,330);
