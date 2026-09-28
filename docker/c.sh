cd /home/amogus/Documents/VulnWatch_SOC_V1/docker

# 1. Arrêter n8n
docker-compose stop n8n

# 2. Supprimer le volume n8n pour réinitialiser
docker-compose rm -f n8n

# 3. Supprimer les données de n8n
docker volume rm docker_n8n-data 2>/dev/null || true

# 4. Générer une nouvelle clé de chiffrement
N8N_ENCRYPTION_KEY=$(openssl rand -base64 32)
echo "Nouvelle clé: $N8N_ENCRYPTION_KEY"

# 5. Mettre à jour .env
sed -i "s/N8N_ENCRYPTION_KEY=.*/N8N_ENCRYPTION_KEY=$N8N_ENCRYPTION_KEY/" .env

# 6. Redémarrer
docker-compose up -d n8n

# 7. Vérifier
docker-compose logs n8n --tail=20
