-- دفتر الأقساط: الجداول والصلاحيات
-- كل حساب يملك بياناته وحده: كل صف يحمل owner_id، وسياسات RLS تمنع أي حساب آخر من قراءته أو تعديله.
create schema if not exists private;

create table public.customers (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name text not null check (length(btrim(name)) between 1 and 120),
  phone text not null default '',
  civil_id text not null default '',
  notes text not null default '',
  created_at timestamptz not null default now(),
  unique (id, owner_id)
);
create index customers_owner_idx on public.customers(owner_id);

create table public.contracts (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  customer_id uuid not null,
  type text not null default 'inst' check (type in ('inst','grace')),
  principal numeric(14,2) not null check (principal > 0),
  total numeric(14,2) not null,
  freq text not null default 'monthly' check (freq in ('monthly','weekly','once')),
  months int check (months between 1 and 120),
  start_date date not null,
  note text not null default '',
  written_off_on date,
  closed_on date,
  closed_note text not null default '',
  created_at timestamptz not null default now(),
  unique (id, owner_id),
  foreign key (customer_id, owner_id) references public.customers(id, owner_id) on delete cascade,
  check (total >= principal),
  check (type <> 'grace' or months is not null)
);
create index contracts_customer_idx on public.contracts(customer_id);
create index contracts_owner_idx on public.contracts(owner_id);

create table public.installments (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  contract_id uuid not null,
  n int not null check (n >= 1),
  due_date date not null,
  amount numeric(14,2) not null check (amount > 0),
  unique (contract_id, n),
  unique (id, owner_id),
  foreign key (contract_id, owner_id) references public.contracts(id, owner_id) on delete cascade
);
create index installments_owner_idx on public.installments(owner_id);

create table public.payments (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  installment_id uuid not null,
  amount numeric(14,2) not null check (amount > 0),
  paid_on date not null default current_date,
  created_at timestamptz not null default now(),
  foreign key (installment_id, owner_id) references public.installments(id, owner_id) on delete cascade
);
create index payments_installment_idx on public.payments(installment_id);
create index payments_owner_idx on public.payments(owner_id);

create table public.settings (
  owner_id uuid primary key default auth.uid() references auth.users(id) on delete cascade,
  zakat_rate numeric(6,4) not null default 2.5 check (zakat_rate in (2.5, 2.5775))
);

-- لا يتجاوز مجموع المدفوعات قيمة القسط
create function private.check_payment() returns trigger
language plpgsql set search_path = '' as $$
declare
  v_amount numeric;
  v_paid numeric;
begin
  select amount into v_amount from public.installments where id = new.installment_id for update;
  select coalesce(sum(amount), 0) into v_paid from public.payments where installment_id = new.installment_id;
  if v_paid + new.amount > v_amount then
    raise exception 'payment exceeds the installment remainder' using errcode = '23514';
  end if;
  return new;
end;
$$;
grant usage on schema private to authenticated;
create trigger payments_check before insert on public.payments
for each row execute function private.check_payment();

-- إنشاء العقد مع جدول أقساطه في عملية واحدة
create function public.create_contract(
  p_customer_id uuid, p_type text, p_principal numeric, p_total numeric,
  p_freq text, p_months int, p_start date, p_note text, p_installments jsonb
) returns uuid
language plpgsql security invoker set search_path = '' as $$
declare
  v_id uuid;
  v_sum numeric;
begin
  if jsonb_typeof(p_installments) <> 'array' or jsonb_array_length(p_installments) not between 1 and 120 then
    raise exception 'installments must be 1 to 120 rows' using errcode = '23514';
  end if;
  select sum((e->>'amount')::numeric) into v_sum from jsonb_array_elements(p_installments) e;
  if v_sum <> p_total then
    raise exception 'installments must add up to the total' using errcode = '23514';
  end if;
  insert into public.contracts (customer_id, type, principal, total, freq, months, start_date, note)
  values (p_customer_id, p_type, p_principal, p_total, p_freq, p_months, p_start, coalesce(p_note, ''))
  returning id into v_id;
  insert into public.installments (contract_id, n, due_date, amount)
  select v_id, (e->>'n')::int, (e->>'due')::date, (e->>'amount')::numeric
  from jsonb_array_elements(p_installments) e;
  return v_id;
end;
$$;
revoke all on function public.create_contract(uuid,text,numeric,numeric,text,int,date,text,jsonb) from public, anon;
grant execute on function public.create_contract(uuid,text,numeric,numeric,text,int,date,text,jsonb) to authenticated;

-- الصلاحيات: لا شيء للزائر، ولكل حساب صفوفه فقط
revoke all on public.customers, public.contracts, public.installments, public.payments, public.settings from anon;
grant select, insert, update, delete on public.customers, public.contracts, public.installments, public.payments to authenticated;
grant select, insert, update on public.settings to authenticated;

alter table public.customers enable row level security;
alter table public.contracts enable row level security;
alter table public.installments enable row level security;
alter table public.payments enable row level security;
alter table public.settings enable row level security;

create policy owner_all on public.customers for all to authenticated
  using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));
create policy owner_all on public.contracts for all to authenticated
  using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));
create policy owner_all on public.installments for all to authenticated
  using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));
create policy owner_all on public.payments for all to authenticated
  using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));
create policy owner_all on public.settings for all to authenticated
  using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));

-- تعديل العقد: الأقساط التي فيها سداد لا تتغير، والباقي يُعاد بناؤه
create function public.update_contract(
  p_contract_id uuid, p_type text, p_principal numeric, p_total numeric,
  p_freq text, p_months int, p_start date, p_note text, p_installments jsonb
) returns void
language plpgsql security invoker set search_path = '' as $$
declare
  v_row record;
  v_sum numeric;
  v_count int;
begin
  if jsonb_typeof(p_installments) <> 'array' or jsonb_array_length(p_installments) not between 1 and 120 then
    raise exception 'installments must be 1 to 120 rows' using errcode = '23514';
  end if;
  perform 1 from public.contracts where id = p_contract_id for update;
  if not found then
    raise exception 'contract not found' using errcode = 'P0002';
  end if;
  select sum((e->>'amount')::numeric) into v_sum from jsonb_array_elements(p_installments) e;
  if v_sum <> p_total then
    raise exception 'installments must add up to the total' using errcode = '23514';
  end if;
  v_count := jsonb_array_length(p_installments);
  if (select count(distinct (e->>'n')::int) from jsonb_array_elements(p_installments) e) <> v_count
     or (select min((e->>'n')::int) from jsonb_array_elements(p_installments) e) <> 1
     or (select max((e->>'n')::int) from jsonb_array_elements(p_installments) e) <> v_count then
    raise exception 'installment numbers must run from 1 to the count' using errcode = '23514';
  end if;
  for v_row in
    select i.n, i.due_date, i.amount from public.installments i
    where i.contract_id = p_contract_id
      and exists (select 1 from public.payments p where p.installment_id = i.id)
  loop
    if not exists (
      select 1 from jsonb_array_elements(p_installments) e
      where (e->>'n')::int = v_row.n
        and (e->>'due')::date = v_row.due_date
        and (e->>'amount')::numeric = v_row.amount
    ) then
      raise exception 'installment % has payments and cannot change', v_row.n using errcode = '23514';
    end if;
  end loop;
  delete from public.installments i
  where i.contract_id = p_contract_id
    and not exists (select 1 from public.payments p where p.installment_id = i.id);
  insert into public.installments (contract_id, n, due_date, amount)
  select p_contract_id, (e->>'n')::int, (e->>'due')::date, (e->>'amount')::numeric
  from jsonb_array_elements(p_installments) e
  where not exists (
    select 1 from public.installments i
    where i.contract_id = p_contract_id and i.n = (e->>'n')::int
  );
  update public.contracts
     set type = p_type, principal = p_principal, total = p_total, freq = p_freq,
         months = p_months, start_date = p_start, note = coalesce(p_note, '')
   where id = p_contract_id;
end;
$$;
revoke all on function public.update_contract(uuid,text,numeric,numeric,text,int,date,text,jsonb) from public, anon;
grant execute on function public.update_contract(uuid,text,numeric,numeric,text,int,date,text,jsonb) to authenticated;
