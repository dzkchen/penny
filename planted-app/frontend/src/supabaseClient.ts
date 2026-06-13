import { createClient } from "@supabase/supabase-js";

export const supabaseUrl = "http://127.0.0.1:8787";
export const anonKey = "sb_anon_penny_demo_public";
export const serviceRoleKey = "sb_service_role_PENNY_DEMO_SUPER_PRIVATE_DO_NOT_SHIP_2026";

export const supabase = createClient(supabaseUrl, serviceRoleKey);
