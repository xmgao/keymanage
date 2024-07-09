/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:25:29
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-08 17:35:33
 * @FilePath: \c\keymanage\project2\src\queue.c
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */

#include "queue.h"
#include <stdlib.h>
#include <stdio.h>

// 初始化队列
void init_queue(Queue *queue)
{
    queue->front = NULL;
    queue->rear = NULL;
}

// 入队
void enqueue(Queue *queue, int data)
{
    QueueNode *new_node = (QueueNode *)malloc(sizeof(QueueNode));
    if (!new_node)
    {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);
    }
    new_node->data = data;
    new_node->next = NULL;
    if (queue->rear)
    {
        queue->rear->next = new_node;
    }
    else
    {
        queue->front = new_node;
    }
    queue->rear = new_node;
}

// 出队
int dequeue(Queue *queue)
{
    if (is_empty(queue))
    {
        perror("Queue underflow");
        exit(EXIT_FAILURE);
    }
    QueueNode *temp = queue->front;
    int data = temp->data;
    queue->front = temp->next;
    if (!queue->front)
    {
        queue->rear = NULL;
    }
    free(temp);
    return data;
}

// 检查队列是否为空
int is_empty(const Queue *queue)
{
    return queue->front == NULL;
}