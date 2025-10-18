}

# --- 4) Monta conjunto final: começa pelos existentes ainda válidos ---
declare -A final_set
for ip in "${!existing[@]}"; do
  if is_within_ttl "$ip"; then
    final_set["$ip"]=1
  else
    # expirado: será removido ao reescrever (não entra no final_set)
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$ip,REMOVED_EXPIRED" >> "$AUDIT_CSV"
  fi
done

# --- 5) Avalia candidatos novos/atuais do SRC ---
for ip in "${!latest_ts[@]}"; do
  ts_label="${latest_ts[$ip]}"
  full_line="${latest_full[$ip]}"

  # Só se a linha tiver action="dropped"
  if ! echo "$full_line" | grep -q 'action="dropped"'; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$ip,IGNORED_NOT_DROPPED,\"$ts_label\",\"$full_line\"" >> "$AUDIT_CSV"
    continue
  fi

  if is_within_ttl "$ip"; then
    # já válido no TTL -> garante presença
    final_set["$ip"]=1
  else
    # novo ou expirado -> (re)inserir e registrar novo timestamp
    final_set["$ip"]=1
    echo "$ip #t=${NOW} #src=\"${ts_label}\" #full=\"${full_line}\"" >> "$PENDING_META"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$ip,ADDED_OR_RENEWED,\"$ts_label\",\"$full_line\"" >> "$AUDIT_CSV"
  fi
done

# --- 6) Escreve saída final (mescla) de forma atômica ---
# (Não perde IPs: inclui existentes válidos + novos válidos; remove apenas expirados)
: > "$TMP"
for ip in "${!final_set[@]}"; do
  echo "$ip" >> "$TMP"
done
sort -u "$TMP" > "${TMP}.uniq"
mv "${TMP}.uniq" "$OUT"
chmod 644 "$OUT"
rm -f "$TMP"

# --- 7) Compacta/limpa PENDING_META apenas para entradas dentro do TTL ---
if [ -f "$PENDING_META" ]; then
  awk -v now="$NOW" -v ttl="$TTL_SECONDS" '
  {
    match($0, /#t=([0-9]+)/, a);
    t = (a[1] ? a[1] : 0);
    if ((now - t) <= ttl) print $0;
  }' "$PENDING_META" > "${PENDING_META}.tmp" && mv "${PENDING_META}.tmp" "$PENDING_META"
fi

echo "Blocklist atualizada -> $OUT (IPs: $(wc -l < "$OUT"))"
