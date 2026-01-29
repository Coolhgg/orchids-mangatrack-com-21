// @ts-nocheck - Script requires pg package types
import pg from 'pg'
const { Client } = pg

async function main() {
  const client = new Client({
    user: 'postgres.nkrxhoamqsawixdwehaq',
    host: 'aws-1-us-east-2.pooler.supabase.com',
    database: 'postgres',
    password: 'hg2604207599980520',
    port: 5432,
  })

  try {
    await client.connect()
    console.log('Connection successful with raw password!')
    const res = await client.query('SELECT 1')
    console.log('Query result:', res.rows)
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : 'Unknown error'
    console.error('Connection failed with raw password:', errorMessage)
  } finally {
    await client.end()
  }
}

main()
