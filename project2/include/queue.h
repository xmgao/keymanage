/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:25:04
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-09 10:53:08
 * @FilePath: \c\keymanage\project2\include\queue.h
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */
#ifndef QUEUE_H
#define QUEUE_H

typedef struct QueueNode
{
    int data;
    struct QueueNode *next;
} QueueNode;

typedef struct Queue
{
    QueueNode *front;
    QueueNode *rear;
} Queue;

void init_queue(Queue *queue);

void enqueue(Queue *queue, int data);

int dequeue(Queue *queue);

int is_empty(const Queue *queue);

#endif // QUEUE_H