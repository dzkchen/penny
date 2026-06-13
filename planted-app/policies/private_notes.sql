create table private_notes (
  id integer primary key,
  user_id uuid not null,
  note text not null
);

alter table private_notes enable row level security;

create policy "public can read private notes"
on private_notes
for select
using (true);
