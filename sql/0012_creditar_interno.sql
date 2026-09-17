-- 0012_creditar_interno.sql — o Clientify precisa de creditar dinheiro
-- novo na conta da empresa quando um pedido é pago (banco_creditar_inicial
-- é exatamente esse mecanismo, mas está gated a fn_e_professor() porque
-- foi pensada só para o fundo inicial que o professor emite à mão).
--
-- Mesmo padrão já usado no EmDia (banco_emitir_fatura/_interna,
-- util_emitir_ciclo/_interno): separa o miolo sem gate (revogado de
-- anon/authenticated, só chamável por outra security definer do mesmo
-- dono) do wrapper público, que continua igual — nenhum comportamento
-- muda para quem já chama banco_creditar_inicial.

create or replace function public.banco_creditar_inicial_interno(
  p_cedula text, p_valor bigint, p_descricao text default 'Crédito', p_categoria text default 'emissao')
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $function$
declare v_conta record; v_id uuid := gen_random_uuid(); v_codigo text;
begin
  if p_valor is null or p_valor <= 0 then
    return jsonb_build_object('ok', false, 'erro', 'Valor tem de ser positivo.');
  end if;
  select * into v_conta from public.contas where cedula = p_cedula for update;
  if not found then
    return jsonb_build_object('ok', false, 'erro', 'Conta inexistente para ' || p_cedula);
  end if;
  update public.contas set saldo = saldo + p_valor where cedula = p_cedula;
  v_codigo := upper(left(encode(digest(v_id::text || now()::text, 'sha256'), 'hex'), 12));
  insert into public.transacoes(id, origem_iban, destino_iban, valor, categoria, descricao, estado, codigo_auth)
  values (v_id, null, v_conta.iban, p_valor, p_categoria, p_descricao, 'concluida', v_codigo);
  return jsonb_build_object('ok', true, 'dados', jsonb_build_object(
    'id', v_id, 'iban', v_conta.iban, 'saldo', v_conta.saldo + p_valor, 'codigo', v_codigo));
exception when others then
  return jsonb_build_object('ok', false, 'erro', 'Falha ao creditar: ' || sqlerrm);
end; $function$;

revoke all on function public.banco_creditar_inicial_interno(text, bigint, text, text) from public, anon, authenticated;

create or replace function public.banco_creditar_inicial(
  p_cedula text, p_valor bigint, p_descricao text default 'Fundo inicial')
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $function$
begin
  if auth.uid() is null then
    return jsonb_build_object('ok', false, 'erro', 'Sem sessão.');
  end if;
  if not public.fn_e_professor() then
    return jsonb_build_object('ok', false, 'erro', 'Só o professor pode emitir fundo inicial.');
  end if;
  return public.banco_creditar_inicial_interno(p_cedula, p_valor, p_descricao, 'emissao');
end; $function$;

-- (grant já existia deste de antes — create or replace não o apaga)
