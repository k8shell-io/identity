SELECT session_id,
       username,
       proxy_id,
       proxy_pid,
       client,
       client_ip,
       start_time,
       end_time,
       workspace,
       bytes_in,
       bytes_out,
       channels,
       prov_time
FROM public.sessions
ORDER BY end_time DESC
LIMIT 1000;

-- Query returned 1000 rows in 0.123 seconds.
SELECT 
    username,
    DATE(start_time) AS day,
    COUNT(*) AS session_count
FROM public.sessions
GROUP BY username, DATE(start_time)
ORDER BY day DESC, username;

-- update all endtime 
