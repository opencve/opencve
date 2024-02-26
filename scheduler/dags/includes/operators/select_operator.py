from airflow.models.baseoperator import BaseOperator
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook


class SelectOperator(BaseOperator):
    def __init__(self, query, reduce_fn, **kwargs) -> None:
        super().__init__(**kwargs)
        self.query = query
        self.reduce_fn = reduce_fn
        self.postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
        self.redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()

    def get_redis_key(self, start, end):
        return f"{self.task_id}_{start}_{end}"

    def execute(self, context):
        start = context.get("data_interval_start")
        end = context.get("data_interval_end").subtract(seconds=1)

        records = self.postgres_hook.get_records(
            sql=self.query, parameters={"start": start, "end": end}
        )

        items = self.reduce_fn(records)
        self.log.info("Retrieved %s items", str(len(items)))
        self.log.info(items)

        if items:
            key = self.get_redis_key(start, end)
            self.redis_hook.json().set(key, "$", items)
            return {"redis_key": key}
