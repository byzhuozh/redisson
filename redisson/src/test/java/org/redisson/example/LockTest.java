package org.redisson.example;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.TimeUnit;

/**
 * @author zhuozh
 * @version : LockTest.java, v 0.1 2020/4/18 18:26 zhuozh Exp $
 */
@Slf4j
public class LockTest {

    public static void main(String[] args) throws Exception {
//        Boolean lockFlag = RedisLockUtil.acquire("key_byzhuozh", 10, TimeUnit.MINUTES);
//        Thread.sleep(10000);
//        RedisLockUtil.release("key_byzhuozh");

        Boolean lockFlag = RedisLockUtil.acquire("lock_key_byzhuozh", 30, TimeUnit.SECONDS);
        RedisLockUtil.acquire("lock_key_byzhuozh", 30, TimeUnit.SECONDS);

        Thread.sleep(-1);
    }

}
