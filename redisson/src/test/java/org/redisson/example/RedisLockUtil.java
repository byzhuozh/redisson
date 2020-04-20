package org.redisson.example;

import lombok.extern.slf4j.Slf4j;
import org.redisson.Redisson;
import org.redisson.api.RLock;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * @author zhuozh
 * @version : RedisLockUtil.java, v 0.1 2020/4/18 13:49 zhuozh Exp $
 */
@Slf4j
@Component
public class RedisLockUtil {

    //从配置类中获取Redisson对象
    private static Redisson redisson = RedissonManager.getRedisson();
    private static final String LOCK_TITLE = "redisLock_";

    //加锁
    public static boolean acquire(String key, long expire, TimeUnit expireUnit) {
        //声明key对象
        key = LOCK_TITLE + key;
        //获取锁对象
        RLock mylock = redisson.getLock(key);
        boolean lockFlag = mylock.isLocked();

        //加锁，并且设置锁过期时间，防止死锁的产生
        mylock.lock(expire, expireUnit);
        log.info("======lock======" + Thread.currentThread().getName());
        //加锁成功
        return true;
    }

    //锁的释放
    public static void release(String lockName) {
        //必须是和加锁时的同一个key
        String key = LOCK_TITLE + lockName;
        //获取所对象
        RLock mylock = redisson.getLock(key);
        //释放锁（解锁）
        mylock.unlock();
        log.info("======unlock======" + Thread.currentThread().getName());
    }

}
